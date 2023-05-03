from SiemplifyUtils import output_handler
# ==============================================================================
# title           :ApplicationConnector.py
# description     :This Module contain SentinelOneV2 Application Connector logic.
# author          :danield@siemplify.co
# date            :27-04-2020
# python_version  :2.7
# libraries       : -
# requirements    :
# ==============================================================================
# =====================================
#              IMPORTS                #
# =====================================
from SentinelOneV2Manager import SentinelOneV2Manager, SentinelOneV2ApiLimitError
from SiemplifyConnectors import SiemplifyConnectorExecution, CaseInfo
from SiemplifyUtils import convert_unixtime_to_datetime, utc_now, unix_now, convert_datetime_to_unix_time, convert_string_to_unix_time, dict_to_flat
from TIPCommon import extract_connector_param
from EnvironmentCommon import EnvironmentHandle
import datetime
import uuid
import sys
import copy

# =====================================
#             CONSTANTS               #
# =====================================
# Existing Event Fields.
EVENT_CREATION_TIME_FIELD = 'createdAt'
EVENT_UUID_FIELD = 'uuid'

# New Additional even fields.
EVENT_CREATION_TIME_UNIXTIME_FIELD = 'creation_time_unix_time'

ALERT_NAME_FIELD = "riskLevel"
APP_NAME = "name"

DEFAULT_PRODUCT = 'SentinelOneV2Applications'
DEFAULT_VENDOR = u'SentinelOneV2Applications'

ALERT_WITHOUT_A_NAME_DEFAULT = 'Application has no name.'


# =====================================
#              CLASSES                #
# =====================================
class SentinelOneV2QueryConnectorError(Exception):
    pass


class SentinelOneV2ApplicationConnector(object):
    def __init__(self, logger):
        self.logger = logger

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

    def convert_app_time_to_unixtime(self, string_time):
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

    @staticmethod
    def create_case(events, query, device_product_field, environment):
        """
        Create a case object.
        :return: {CaseInfo}
        """
        case_info = CaseInfo()
        case_info.start_time = case_info.end_time = events.get('created_at_unixtime')
        case_info.device_product = events.get(device_product_field, DEFAULT_PRODUCT)
        case_info.device_vendor = DEFAULT_VENDOR
        case_info.name = "{}({})".format(events.get(APP_NAME),
                                         events.get(ALERT_NAME_FIELD, ALERT_WITHOUT_A_NAME_DEFAULT))
        case_info.ticket_id = events.get(EVENT_UUID_FIELD, "{0}_{1}".format(case_info.start_time,
                                                                            str(uuid.uuid4())))

        case_info.rule_generator = query
        case_info.device_vendor = case_info.device_product
        case_info.environment = environment

        # If no Session ID, replace with timestamp + uuid because timestamp can be not unique in some cases.

        case_info.display_id = case_info.identifier = case_info.ticket_id

        case_info.events = [events]
        return case_info


@output_handler
def main(test_handler=False):
    connector_scope = SiemplifyConnectorExecution()
    output_variables = {}
    log_items = []
    cases = []
    apps = []

    try:
        if test_handler:
            connector_scope.LOGGER.info(
                " ------------ Starting SentinelOneV2 Application Connector test. ------------ ")
        else:
            connector_scope.LOGGER.info(" ------------ Starting Connector. ------------ ")

        api_root = extract_connector_param(connector_scope, u"API Root", is_mandatory=True)
        api_token = extract_connector_param(connector_scope, u"API Token", is_mandatory=True)
        app_risk_level = extract_connector_param(connector_scope, u"App Risk", is_mandatory=True).split(
            ",") if extract_connector_param(connector_scope,
                                            u"App Risk") else []
        verify_ssl = extract_connector_param(connector_scope, u"Verify SSL", is_mandatory=True, input_type=bool)
        max_days_backwards = extract_connector_param(connector_scope, param_name=u"Fetch Max Days Backwards",
                                                     is_mandatory=False, default_value=1, input_type=int,
                                                     print_value=True)
        events_limit = extract_connector_param(connector_scope, param_name=u"Event Count Limit", is_mandatory=False,
                                               default_value=50, input_type=int, print_value=True)
        device_product_field = extract_connector_param(connector_scope, u"DeviceProductField", is_mandatory=True)

        sentinel_manager = SentinelOneV2Manager(api_root, api_token, verify_ssl)
        sentinel_connector = SentinelOneV2ApplicationConnector(connector_scope.LOGGER)

        last_run_time = int((sentinel_connector.validate_timestamp_offset(
            connector_scope.fetch_timestamp(datetime_format=True),
            max_days_backwards)).strftime("%s")) * 1000

        current_time = unix_now()
        between_time = "{0}-{1}".format(last_run_time, current_time)

        for risk in app_risk_level:
            connector_scope.LOGGER.info('Getting "{0}" risk applications.'.format(unicode(risk).encode('utf-8')))
            try:
                if test_handler:
                    applications = sentinel_manager.get_installed_applications(risk_level=risk,
                                                                               installed_between=between_time,
                                                                               limit=2)
                else:
                    applications = sentinel_manager.get_installed_applications(risk_level=risk,
                                                                               installed_between=between_time,
                                                                               limit=events_limit)

                for app in applications:
                    agent_uuid = app.get('agentUuid')
                    app_id = app.get('id')
                    app['created_at_unixtime'] = (
                        sentinel_connector.convert_app_time_to_unixtime(app.get(EVENT_CREATION_TIME_FIELD)))

                    flat_apps = dict_to_flat(app)

                    connector_scope.LOGGER.info(
                        'Found "{0}" Applications with a risk level of "{1}"'.format(len(applications), unicode(
                            risk).encode('utf-8')))

                    connector_scope.LOGGER.info('Creating case for risk: "{0}"'.format(unicode(risk).encode('utf-8')))
                    case = sentinel_connector.create_case(
                        flat_apps,
                        query=risk,
                        device_product_field=device_product_field,
                        environment=connector_scope.context.connector_info.environment)

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
                error_message = "Failed fetching applications with {0} risk".format(
                    unicode(risk).encode('utf-8'))
                connector_scope.LOGGER.error(error_message)
                connector_scope.LOGGER.exception(err)
                if test_handler:
                    raise

        if test_handler:
            connector_scope.LOGGER.info(
                " ------------ Complete SentinelOneV2 Application Connector test. ------------ ")
        else:
            connector_scope.LOGGER.info(" ------------ Complete Connector Iteration. ------------ ")

        # sentinel_manager.logout()
        if not test_handler:
            connector_scope.save_timestamp(current_time)
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
