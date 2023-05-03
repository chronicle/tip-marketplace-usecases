from SiemplifyUtils import output_handler
# ==============================================================================
# title           :ThreatsConnector.py
# description     :This Module contain SentinelOneV2 threats Connector logic.
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
from SentinelOneV2Manager import SentinelOneV2Manager
from SiemplifyConnectors import SiemplifyConnectorExecution, CaseInfo
from SiemplifyUtils import convert_string_to_unix_time, dict_to_flat, utc_now
from TIPCommon import extract_connector_param
from EnvironmentCommon import EnvironmentHandle
import uuid
import sys
import datetime
import os
import json

# =====================================
#             CONSTANTS               #
# =====================================
EVENT_CREATION_TIME_FIELD = 'agent_createdAt'
DEFAULT_PRODUCT = 'SentinelOne'
MAP_FILE = u"map.json"

EVENT_TIME_FIELD = 'createdAt'
THREAT_DESCRIPTION_FIELD = 'description'
THREAT_NAME_FIELD = "threatName"
THREAT_ID_FIELD = "id"

ALERT_WITHOUT_A_RULE_DEFAULT = 'Alert has no rule.'
ALERT_WITHOUT_A_NAME_DEFAULT = 'Alert has no name.'
THREAT_NAME_IS_EMPTY_DEFAULT = "Threat name is empty."


# =====================================
#              CLASSES                #
# =====================================
class SentinelOneV2ThreatsConnectorError(Exception):
    pass


class SentinelOneV2ThreatsConnector(object):
    def __init__(self, connector_scope, environment_field_name, environment_regex, logger):
        self.connector_scope = connector_scope
        self.logger = logger

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
    def validate_timestamp_offset(datetime_timestamp, offset_in_days=2):
        """
        Validate if timestamp in offset range.
        :param datetime_timestamp: timestamp that were fetched from the timestamp file {datetime}
        :param offset_in_days: the offset in days to validate {string}
        :return: unixtime: if time not in offset return offset time {string}
        """
        offset_datetime = utc_now() - datetime.timedelta(days=offset_in_days)

        if datetime_timestamp <= offset_datetime:
            return offset_datetime
        return datetime_timestamp

    def convert_threat_time_to_unixtime(self, string_time):
        """
        Convert threat time from string format to unixtime.
        :param string_time: {stirng} Time string.
        :return: {long} Time unixtime.
        """
        try:
            return convert_string_to_unix_time(string_time)
        except Exception as err:
            error_message = "Failed to convert threat time, ERROR: {0}".format(err.message)
            self.logger.error(error_message)
            self.logger.exception(err)
            return 1

    def create_case(self, threat, device_product_field):
        """
        Create a case object.
        :return: {CaseInfo} Case object.
        """
        case_info = CaseInfo()
        case_info.start_time = case_info.end_time = self.convert_threat_time_to_unixtime(threat.get(EVENT_TIME_FIELD))
        case_info.rule_generator = threat.get(THREAT_DESCRIPTION_FIELD, ALERT_WITHOUT_A_RULE_DEFAULT)
        case_info.device_product = threat.get(device_product_field, DEFAULT_PRODUCT)
        case_info.device_vendor = case_info.device_product
        case_info.environment = self.environment_common.get_environment(threat)

        case_info.name = threat.get(THREAT_NAME_FIELD, ALERT_WITHOUT_A_NAME_DEFAULT) \
            if threat.get(THREAT_NAME_FIELD) else THREAT_NAME_IS_EMPTY_DEFAULT

        # If no Session ID, replace with timestamp + uuid because timestamp can be not unique in some cases.
        case_info.ticket_id = threat.get(THREAT_ID_FIELD, "{0}_{1}".format(case_info.start_time,
                                                                           str(uuid.uuid4())))

        case_info.display_id = case_info.identifier = case_info.ticket_id
        case_info.events = [dict_to_flat(threat)]

        return case_info


@output_handler
def main(test_handler=False):
    connector_scope = SiemplifyConnectorExecution()
    output_variables = {}
    log_items = []
    cases = []
    whole_cases_list = []

    try:
        if test_handler:
            connector_scope.LOGGER.info(" ------------ Starting SentinelOneV2 Threats Connector test. ------------ ")
        else:
            connector_scope.LOGGER.info(" ------------ Starting Connector. ------------ ")

        api_root = extract_connector_param(connector_scope, u"API Root", is_mandatory=True)
        api_token = extract_connector_param(connector_scope, u"API Token", is_mandatory=True)
        verify_ssl = extract_connector_param(connector_scope, u"Verify SSL", is_mandatory=True, input_type=bool)
        max_days_backwards = extract_connector_param(connector_scope, param_name=u"Fetch Max Days Backwards",
                                                     is_mandatory=False, default_value=1, input_type=int,
                                                     print_value=True)
        device_product_field = extract_connector_param(connector_scope, u"DeviceProductField", is_mandatory=True)
        environment_field_name = extract_connector_param(connector_scope, param_name=u"Environment Field Name",
                                                         is_mandatory=False, input_type=unicode, print_value=True)
        environment_regex = extract_connector_param(connector_scope, param_name=u"Environment Regex Pattern",
                                                    is_mandatory=False, input_type=unicode, print_value=True)

        sentinel_manager = SentinelOneV2Manager(api_root, api_token, verify_ssl)
        sentinel_connector = SentinelOneV2ThreatsConnector(connector_scope, environment_field_name, environment_regex,
                                                           connector_scope.LOGGER)

        last_run_time = sentinel_connector.validate_timestamp_offset(
            connector_scope.fetch_timestamp(datetime_format=True),
            max_days_backwards)

        threats = sentinel_manager.get_unresolved_threats_by_time(last_run_time)

        threats = map(dict_to_flat, threats)

        if test_handler:
            threats = threats[-1:]

        for threat in threats:
            try:
                agent_id = threat.get('agentId')

                if agent_id:
                    connector_scope.LOGGER.info(
                        "Retrieving agent information for threat with id: {0}".format(threat.get(THREAT_ID_FIELD)))
                    agent_info = sentinel_manager.get_agent_by_id(agent_id)
                    threat['agent'] = agent_info.to_json()

                connector_scope.LOGGER.info("Creating case for threat with id: {0}".format(threat.get(THREAT_ID_FIELD)))
                case = sentinel_connector.create_case(
                    threat,
                    device_product_field=device_product_field)
                whole_cases_list.append(case)

                is_overflowed = False

                try:
                    is_overflowed = connector_scope.is_overflowed_alert(
                        environment=case.environment,
                        alert_identifier=str(case.ticket_id),
                        alert_name=str(case.rule_generator),
                        product=str(case.device_product))

                except Exception as err:
                    connector_scope.LOGGER.error(
                        'Error validation connector overflow, ERROR: {0}'.format(unicode(err)))
                    connector_scope.LOGGER.exception(err)
                    if test_handler:
                        raise

                if is_overflowed:
                    connector_scope.LOGGER.info(
                        "{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping."
                            .format(alert_name=str(case.rule_generator),
                                    alert_identifier=str(case.ticket_id),
                                    environment=str(case.environment),
                                    product=str(case.device_product)))
                else:
                    cases.append(case)
                    connector_scope.LOGGER.info('Case with display id "{0}" was created.'.format(case.display_id))

            except Exception as err:
                error_message = "Failed creating case for threat with ID: {0}, ERROR: {1}".format(
                    threat.get(THREAT_ID_FIELD),
                    err.message
                )
                connector_scope.LOGGER.error(error_message)
                connector_scope.LOGGER.exception(err)
                if test_handler:
                    raise

        whole_cases_list.sort(key=lambda x: x.start_time)

        if whole_cases_list and not test_handler:
            connector_scope.save_timestamp(whole_cases_list[-1].start_time)

        if test_handler:
            connector_scope.LOGGER.info(" ------------ Complete SentinelOneV2 Threat Connector test. ------------ ")
        else:
            connector_scope.LOGGER.info(" ------------ Complete Connector Iteration. ------------ ")

        connector_scope.return_package(cases, output_variables, log_items)

    except Exception as err:
        connector_scope.LOGGER.error('Got exception on main handler. Error: {0}'.format(err))
        connector_scope.LOGGER.exception(err)
        if test_handler:
            raise


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'True':
        print "Main execution started"
        main()
    else:
        print "Test execution started"
        main(test_handler=True)
