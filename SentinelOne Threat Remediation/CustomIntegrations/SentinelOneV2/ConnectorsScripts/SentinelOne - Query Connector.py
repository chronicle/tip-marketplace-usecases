from SiemplifyUtils import output_handler
# ==============================================================================
# title           :QueryConnector.py
# description     :This Module contain SentinelOneV2 query Connector logic.
# author          :victor@siemplify.co
# date            :28-11-2018
# python_version  :2.7
# libraries       : -
# requirements    :
# product_version : Eiffel
# ==============================================================================
# =====================================
#              IMPORTS                #
# =====================================
from SentinelOneV2Manager import SentinelOneV2Manager, SentinelOneV2ApiLimitError
from SiemplifyConnectors import SiemplifyConnectorExecution, CaseInfo
from SiemplifyUtils import convert_unixtime_to_datetime, utc_now, unix_now, convert_datetime_to_unix_time
from TIPCommon import extract_connector_param
from EnvironmentCommon import EnvironmentHandle
import datetime
import time
import arrow
import uuid
import json
import sys
import os

# =====================================
#             CONSTANTS               #
# =====================================
MAP_FILE = u"map.json"
TIMELINE_FILE = u"timeline.json"
IDS_FILE = u"ids.json"
SEVERITY_KEY = u"Severity:::"
QUERY_KEY = u"Query:::"

SEVERITIES = {
    u"Critical": 100,
    u"High": 80,
    u"Medium": 60,
    u"Low": 40,
    u"Info": -1
}

DEFAULT_PRODUCT = u'SentinelOne'
DEFAULT_VENDOR = u'SentinelOne'

ALERT_WITHOUT_A_NAME_DEFAULT = u'Alert has no name.'
ALERT_NAME_FORMAT = u"SentinelOne Query: {} Alert"
ALERT_DESCRIPTION_FORMAT = u"Alert generated based on the events found by executing SentinelOne Query: {}"


# =====================================
#              CLASSES                #
# =====================================


class SentinelOneV2QueryConnectorError(Exception):
    pass


class SentinelOneV2QueryConnector(object):
    def __init__(self, connector_scope, environment_field_name, environment_regex):
        self.connector_scope = connector_scope
        self.logger = connector_scope.LOGGER

        map_file_path = os.path.join(connector_scope.run_folder, MAP_FILE)
        connector_scope.LOGGER.info(u"Validating environments mapping file at: {}".format(map_file_path))
        self.validate_map_file(map_file_path)

        connector_scope.LOGGER.info(u"Loading EnvironmentCommon")
        self.environment_common = EnvironmentHandle(map_file_path, self.logger, environment_field_name,
                                                    environment_regex,
                                                    connector_scope.context.connector_info.environment)

    def validate_map_file(self, map_file_path):
        """
        Validate the existence of the environment mapping file
        :param map_file_path: {str} The path to the map file
        """
        try:
            if not os.path.exists(map_file_path):
                with open(map_file_path, 'w+') as map_file:
                    map_file.write(json.dumps(
                        {u"Original environment name": u"Desired environment name",
                         u"Env1": u"MyEnv1"}))
                    self.logger.info(
                        u"Mapping file was created at {}".format(map_file_path)
                    )

        except Exception as e:
            self.logger.error(u"Unable to create mapping file: {}".format(e))
            self.logger.exception(e)

    @staticmethod
    def validate_timestamp(last_run_timestamp, offset_in_hours):
        """
        Validate timestamp in range
        :param last_run_timestamp: {datetime} last run timestamp
        :param offset_in_hours: The max offset allowed in hours
         offset: {datetime} last run timestamp
        :return: {datetime} if first run, return current time minus offset time, else return timestamp from file
        """
        current_time = utc_now()
        # Check if first run
        if current_time - last_run_timestamp > datetime.timedelta(hours=offset_in_hours):
            return current_time - datetime.timedelta(hours=offset_in_hours)
        else:
            return last_run_timestamp

    def read_timelines(self, queries):
        """
        Read timelines from the timeline.json file
        :param queries: {list} List of parsed queries to fetch timelines for
        :return:{dict} A dict describing the already seen ids {id: the unixtime when it was first seen}
        """
        timeline_file_path = os.path.join(self.connector_scope.run_folder, TIMELINE_FILE)
        self.logger.info(u"Fetching timeline from: {0}".format(timeline_file_path))

        try:
            if not os.path.exists(timeline_file_path):
                self.logger.info(u"Timeline file doesn't exist at path {}".format(timeline_file_path))
                return {}

            with open(timeline_file_path, 'r') as f:
                self.logger.info(u"Reading timetamps from timeline file")
                timestamps = json.loads(f.read())

                filtered_timestamps = {}
                # Insert IDs that did not passed time retention time limit.
                for query, timestamp in timestamps.items():
                    if query in queries:
                        filtered_timestamps[query] = timestamp

                return filtered_timestamps

        except Exception as e:
            self.logger.error(u"Unable to read timeline file: {}".format(e))
            self.logger.exception(e)
            return {}

    def write_timelines(self, timeline_file_path, timestamps):
        """
        Write timestamps to the timeline file
        :param timeline_file_path: {str} The path of the timeline file.
        :param timestamps: {dict} The timestamps to write to the file
        """
        try:
            self.logger.info(u"Writing timestamps to file: {}".format(timeline_file_path))

            if not os.path.exists(os.path.dirname(timeline_file_path)):
                self.logger.info(u"Timeline file doesn't exist at {}. Creating new file.".format(timeline_file_path))
                os.makedirs(os.path.dirname(timeline_file_path))

            with open(timeline_file_path, 'w') as f:
                try:
                    for chunk in json.JSONEncoder().iterencode(timestamps):
                        f.write(chunk)
                except:
                    # Move seeker to start of the file
                    f.seek(0)
                    # Empty the content of the file (the partially written content that was written before the exception)
                    f.truncate()
                    # Write an empty dict to the events data file
                    f.write("{}")
                    raise

        except Exception as e:
            self.logger.error(u"Failed writing timestamps to timeline file, ERROR: {0}".format(e))
            self.logger.exception(e)

    def read_ids(self, cast_keys_to_int=False, max_hours_backwards=24):
        """
        Read existing (arleady seen) alert ids from the ids.json file
        :param cast_keys_to_int: {bool} Whether to case the ids to int or not
        :param max_hours_backwards: {int} Max amount of hours to keep ids in the file (to prevent it from getting too big)
        :return:{dict} A dict describing the already seen ids {id: the unixtime when it was first seen}
        """
        ids_file_path = os.path.join(self.connector_scope.run_folder, IDS_FILE)
        self.logger.info(u"Fetching existing IDs from: {0}".format(ids_file_path))

        try:
            if not os.path.exists(ids_file_path):
                self.logger.info(u"Ids file doesn't exist at path {}".format(ids_file_path))
                return {}

            with open(ids_file_path, 'r') as f:
                self.logger.info(u"Reading existing ids from ids file")
                existing_ids = json.loads(f.read())

                filtered_ids = {}
                # Insert IDs that did not passed time retention time limit.
                for alert_id, timestamp in existing_ids.items():
                    if timestamp > arrow.utcnow().shift(hours=-max_hours_backwards).timestamp * 1000:
                        filtered_ids[alert_id] = timestamp

                if cast_keys_to_int:
                    return {int(k): v for k, v in filtered_ids.items()}

                return filtered_ids

        except Exception as e:
            self.logger.error(u"Unable to read ids file: {}".format(e))
            self.logger.exception(e)
            return {}

    def write_ids(self, ids_file_path, ids):
        """
        Write ids to the ids file
        :param ids_file_path: {str} The path of the ids file.
        :param ids: {dict} The ids to write to the file
        """
        try:
            self.logger.info(u"Writing ids to file: {}".format(ids_file_path))

            if not os.path.exists(os.path.dirname(ids_file_path)):
                self.logger.info(u"Ids file doesn't exist at {}. Creating new file.".format(ids_file_path))
                os.makedirs(os.path.dirname(ids_file_path))

            with open(ids_file_path, 'w') as f:
                try:
                    for chunk in json.JSONEncoder().iterencode(ids):
                        f.write(chunk)
                except:
                    # Move seeker to start of the file
                    f.seek(0)
                    # Empty the content of the file (the partially written content that was written before the exception)
                    f.truncate()
                    # Write an empty dict to the events data file
                    f.write("{}")
                    raise

        except Exception as e:
            self.logger.error(u"Failed writing IDs to IDs file, ERROR: {0}".format(e))
            self.logger.exception(e)

    def filter_old_ids(self, alert_ids, existing_ids):
        """
        Filter ids that were already processed
        :param alert_ids: {list} The ids to filter
        :param existing_ids: {list} The ids to filter
        :return: {list} The filtered ids
        """
        new_alert_ids = []

        for correlated_event_id in alert_ids:
            if correlated_event_id not in existing_ids.keys():
                new_alert_ids.append(correlated_event_id)

        return new_alert_ids

    def parse_queries(self, queries):
        """
        Parse the list of queries
        :param queries: {list} List of unicode query + severity queries, in the following format:
            Query::: ProcessImagePath CONTAINS "windows" Severity::: Medium
        :return: {list} List of parsed queries (tuples) - (parsed query, severity)
        """
        parsed_queries = []

        for query in queries:
            self.logger.info(u"Parsing query: {}".format(query))

            if SEVERITY_KEY not in query:
                self.logger.info(u"\"Severity:::\" key is missing. Medium will be used.")
                severity = SEVERITIES[u"Medium"]
                split_query = query
            else:
                split_query, severity_name = query.rsplit(SEVERITY_KEY, 1)
                severity_name = severity_name.strip()

                if severity_name not in SEVERITIES.keys():
                    self.logger.info(
                        u"Parsed severity \"{}\" is invalid. Valid severities are Critical, High, Medium, Low, Info. Medium will be used.")
                    severity = SEVERITIES[u"Medium"]

                else:
                    severity = SEVERITIES[severity_name]
                    self.logger.info(u"Parsed severity: {} ({})".format(severity, severity_name))

            if QUERY_KEY not in split_query:
                self.logger.info(u"\"Query:::\" key is missing. Current query will be skipped: {}".format(query))
                continue

            parsed_query = split_query.split(QUERY_KEY)[-1]
            self.logger.info(u"Parsed query: {}".format(parsed_query))
            parsed_queries.append((parsed_query, severity))

        return parsed_queries

    def create_case(self, events, query, severity, device_product_field):
        """
        Create a case object.
        :return: {CaseInfo}
        """
        case_info = CaseInfo()
        sorted_events = sorted(events, key=lambda event: event.created_at)

        case_info.start_time = sorted_events[0].creation_time_unix_time
        case_info.end_time = sorted_events[-1].creation_time_unix_time
        case_info.device_product = sorted_events[0].raw_data.get(device_product_field, DEFAULT_PRODUCT)
        case_info.name = ALERT_NAME_FORMAT.format(query)
        case_info.ticket_id = sorted_events[0].uuid or u"{0}_{1}".format(case_info.start_time, unicode(uuid.uuid4()))
        case_info.priority = severity
        case_info.description = ALERT_DESCRIPTION_FORMAT.format(query)
        case_info.environment = self.environment_common.get_environment(sorted_events[0].raw_data)
        case_info.rule_generator = query
        case_info.device_vendor = DEFAULT_VENDOR
        case_info.display_id = case_info.identifier = case_info.ticket_id
        case_info.events = [event.to_event() for event in events]

        return case_info


@output_handler
def main(test_handler=False):
    connector_scope = SiemplifyConnectorExecution()
    output_variables = {}
    log_items = []
    all_cases = []
    cases = []

    try:
        if test_handler:
            connector_scope.LOGGER.info(u" ------------ Starting SentinelOneV2 Query Connector test. ------------ ")
        else:
            connector_scope.LOGGER.info(u" ------------ Starting Connector. ------------ ")

        api_root = extract_connector_param(connector_scope, u"API Root", is_mandatory=True)
        api_token = extract_connector_param(connector_scope, u"API Token", is_mandatory=True)
        verify_ssl = extract_connector_param(connector_scope, u"Verify SSL", is_mandatory=True, input_type=bool)
        max_hours_backwards = extract_connector_param(connector_scope, param_name=u"Max Hour Backwards",
                                                      is_mandatory=False, default_value=1, input_type=int,
                                                      print_value=True)
        events_limit = extract_connector_param(connector_scope, param_name=u"Event Count Limit", is_mandatory=False,
                                               default_value=50, input_type=int, print_value=True)
        device_product_field = extract_connector_param(connector_scope, u"DeviceProductField", is_mandatory=True)
        environment_field_name = extract_connector_param(connector_scope, param_name=u"Environment Field Name",
                                                         is_mandatory=False, input_type=unicode, print_value=True)
        environment_regex = extract_connector_param(connector_scope, param_name=u"Environment Regex Pattern",
                                                    is_mandatory=False, input_type=unicode, print_value=True)

        queries = connector_scope.whitelist

        sentinel_manager = SentinelOneV2Manager(api_root, api_token, verify_ssl, logger=connector_scope.LOGGER)
        sentinel_connector = SentinelOneV2QueryConnector(connector_scope, environment_field_name, environment_regex)

        if not queries:
            connector_scope.LOGGER.error(u"Please add SentinelOne queries to the whitelist.")
            raise Exception(u"Please add SentinelOne queries to the whitelist")

        connector_scope.LOGGER.info(u"Parsing {} queries.".format(len(queries)))
        parsed_queries = sentinel_connector.parse_queries(queries)

        if not parsed_queries:
            connector_scope.LOGGER.error(
                u"No valid queries were parsed. Please add valid SentinelOne queries to the whitelist.")
            raise Exception(u"No valid queries were parsed. Please add valid SentinelOne queries to the whitelist.")

        fallback_timestamp = arrow.utcnow().shift(hours=-max_hours_backwards).datetime
        to_date = unix_now()

        existing_ids = sentinel_connector.read_ids(max_hours_backwards=72)
        # Get the existing timestamps dict for the current queries
        timestamps = sentinel_connector.read_timelines([parsed_query[0] for parsed_query in parsed_queries])

        for query, severity in parsed_queries:
            connector_scope.LOGGER.info(u'Running query "{}".'.format(query))
            try:
                if query not in timestamps:
                    # Current query doesn't have a timestamp in the timeline file
                    connector_scope.LOGGER.info(
                        u"Query \"{}\" doesnt have a timestamp in the timeline file. Setting to fallback timestamp: {}".format(
                            query, fallback_timestamp.isoformat())
                    )
                    query_last_run_timestamp = convert_datetime_to_unix_time(fallback_timestamp)

                else:
                    query_last_run_timestamp = timestamps[query]

                connector_scope.LOGGER.info(u"Running query from {} to {}".format(
                    convert_unixtime_to_datetime(query_last_run_timestamp),
                    convert_unixtime_to_datetime(to_date)
                ))

                query_id = sentinel_manager.initialize_query(
                    query=query,
                    from_date=query_last_run_timestamp,
                    to_date=to_date
                )

                connector_scope.LOGGER.info(
                    u"Successfully initialized query {} fetching query. Query ID: {}. Pending for query to finish.".format(
                        query, query_id)
                )

                while not sentinel_manager.is_query_completed(query_id):
                    connector_scope.LOGGER.info(u"Query {} is not finished yet. Waiting.".format(query_id))
                    time.sleep(1)

                if sentinel_manager.is_query_failed(query_id):
                    connector_scope.LOGGER.error(
                        u"Query {} has failed with status {}.".format(
                            query_id,
                            sentinel_manager.get_query_status(query_id)
                        )
                    )
                    continue

                if not sentinel_manager.is_query_has_results(query_id):
                    connector_scope.LOGGER.info(u"Query {} completed but not events were found.".format(query_id))
                    continue

                connector_scope.LOGGER.info(u"Query {} completed. Collecting events.".format(query_id))

                try:
                    if test_handler:
                        events = sentinel_manager.get_all_events_by_query_id(query_id, limit=1, existing_hashes=existing_ids)
                    else:
                        events = sentinel_manager.get_all_events_by_query_id(query_id, limit=events_limit,
                                                                             existing_hashes=existing_ids)
                except SentinelOneV2ApiLimitError as e:
                    connector_scope.LOGGER.error(e)
                    # Increase the timestamp of the query by 1ms to advance the connector
                    if query in timestamps:
                        timestamps[query] = timestamps[query] + 1
                    else:
                        # Cant really get in here (cause if all 1000 events were already seen, then we must have a
                        # timestamp. But if some catastrophe happened and timeline.json got deleted but ids.json
                        # did not, then just set it to fallback timestamp to avoid the connector from crushing
                        timestamps[query] = convert_datetime_to_unix_time(fallback_timestamp)
                    connector_scope.LOGGER.info(
                        u"Setting query \"{}\" to: {}".format(query, convert_unixtime_to_datetime(timestamps[query]))
                    )

                    break

                if not events:
                    connector_scope.LOGGER.info(
                        u"No new events were found for query {}. No case will be created.".format(query_id)
                    )
                    continue

                connector_scope.LOGGER.info(u'Found {} new events for query {}'.format(len(events), query_id))

                connector_scope.LOGGER.info(u'Creating case for query "{}"'.format(query))
                case = sentinel_connector.create_case(
                    events,
                    query=query,
                    severity=severity,
                    device_product_field=device_product_field
                )

                # Set the timestamp of the query to the case.end_time = the createdAt timestamp of the newest processed
                # event
                connector_scope.LOGGER.info(
                    u"Query \"{}\" new timestamp: {}".format(query, convert_unixtime_to_datetime(case.end_time))
                )
                timestamps[query] = case.end_time
                all_cases.append(case)

                for event in events:
                    # Add the found events to the existing_ids dict and ids.json to stop the connector from fetching
                    # them again in the future
                    existing_ids.update({event.to_hash(): unix_now()})

                is_overflowed = False

                try:
                    is_overflowed = connector_scope.is_overflowed_alert(
                        environment=case.environment,
                        alert_identifier=case.ticket_id,
                        alert_name=case.rule_generator,
                        product=case.device_product
                    )

                except Exception as err:
                    connector_scope.LOGGER.error(
                        u'Error validation connector overflow, ERROR: {}'.format(err))
                    connector_scope.LOGGER.exception(err)
                    if test_handler:
                        raise

                if is_overflowed:
                    connector_scope.LOGGER.info(
                        u"{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping."
                            .format(alert_name=unicode(case.rule_generator),
                                    alert_identifier=unicode(case.ticket_id),
                                    environment=unicode(case.environment),
                                    product=unicode(case.device_product)))
                else:
                    cases.append(case)
                    connector_scope.LOGGER.info(u'Case with display id {} was created.'.format(case.display_id))

            except Exception as err:
                error_message = u"Failed fetching events and creating case for query \"{}\"".format(query)
                connector_scope.LOGGER.error(error_message)
                connector_scope.LOGGER.exception(err)

                if test_handler:
                    raise

        connector_scope.LOGGER.info(u"Created {} cases.".format(len(cases)))

        if not test_handler and all_cases:
            sentinel_connector.write_ids(os.path.join(connector_scope.run_folder, IDS_FILE), existing_ids)
            sentinel_connector.write_timelines(os.path.join(connector_scope.run_folder, TIMELINE_FILE), timestamps)

        if test_handler:
            connector_scope.LOGGER.info(u" ------------ Complete SentinelOneV2 Query Connector test. ------------ ")
        else:
            connector_scope.LOGGER.info(u" ------------ Complete Connector Iteration. ------------ ")

        connector_scope.return_package(cases, output_variables, log_items)

    except Exception as err:
        connector_scope.LOGGER.error(u'Got exception on main handler. Error: {0}'.format(err))
        connector_scope.LOGGER.exception(err)
        if test_handler:
            raise


if __name__ == u"__main__":
    if len(sys.argv) < 2 or sys.argv[1] == u'True':
        print u"Main execution started"
        main()
    else:
        print u"Test execution started"
        main(test_handler=True)
