from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from SlackManager import SlackManager, SlackManagerException
from TIPCommon import extract_configuration_param

SCRIPT_NAME = u'Slack Custom - Ping'
PROVIDER_NAME = u'Slack Custom'

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    api_token = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="ApiToken",
        input_type=unicode
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
        input_type=bool
    )

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        slack_manager = SlackManager(api_token, verify_ssl)
        slack_manager.test_connectivity()
        output_message = u'Connection to Slack established successfully.'
        result = 'true'
        status = EXECUTION_STATE_COMPLETED
        siemplify.LOGGER.info(u'Script Name: {} | {}'.format(SCRIPT_NAME, output_message))
    except SlackManagerException as e:
        output_message = u'An error occurred when trying to connect to the API: {}'.format(e)
        result = 'false'
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(u'Script Name: {} | {}'.format(SCRIPT_NAME, output_message))
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u'Status: {}'.format(status))
    siemplify.LOGGER.info(u'Result: {}'.format(result))
    siemplify.LOGGER.info(u'Output Message: {}'.format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
