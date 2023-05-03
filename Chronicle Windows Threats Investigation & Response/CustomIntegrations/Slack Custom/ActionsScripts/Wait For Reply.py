from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SlackManager import SlackManager, SlackManagerException
from TIPCommon import extract_configuration_param, extract_action_param

SCRIPT_NAME = u'Slack - WaitForReply'
PROVIDER_NAME = u'Slack'


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

    ts = extract_action_param(
        siemplify,
        param_name="Message Timestamp",
        is_mandatory=True,
        print_value=True,
        input_type=unicode
    )

    channel_name = extract_action_param(
        siemplify,
        param_name="Channel",
        is_mandatory=False,
        print_value=True,
        input_type=unicode
    )

    channel_id = extract_action_param(
        siemplify,
        param_name="Channel ID",
        is_mandatory=False,
        print_value=True,
        input_type=unicode
    )

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        slack_manager = SlackManager(api_token, verify_ssl)

        if not (channel_name or channel_id):
            siemplify.LOGGER.error(u"Either Channel or Channel ID parameters must be specified. Aborting.")
            siemplify.end(u"Either Channel or Channel ID parameters must be specified. Aborting.", u'false', EXECUTION_STATE_FAILED)

        if channel_id:
            if channel_name:
                siemplify.LOGGER.warn(u"Both Channel and Channel ID parameters were provided. Only Channel ID will be used.")
            siemplify.LOGGER.info(u"Fetching replies for channel {}".format(channel_id))
            replies = slack_manager.get_message_replies(channel_id, ts)

        else:
            siemplify.LOGGER.info(u"Fetching channel ID for channel {}".format(channel_name))
            channel = slack_manager.get_channel_by_name(channel_name)
            siemplify.LOGGER.info(u"Fetching replies for channel {}".format(channel_id))
            replies = slack_manager.get_message_replies(channel.id, ts)

        if replies:
            # At least one reply was found - take the first
            replies = sorted(replies, key=lambda reply: reply.ts)
            first_reply = replies[0]
            output_message = u'A reply was found for the message in the channel. Reply content: {}'.format(
                first_reply.text)
            siemplify.result.add_result_json(first_reply.raw_data)
            result = 'true'
            status = EXECUTION_STATE_COMPLETED
            siemplify.LOGGER.info(u'Script Name: {} | {}'.format(SCRIPT_NAME, output_message))

        else:
            # There are no replies
            output_message = u'No replies were found for the message in the channel, waiting.'
            result = 'true'
            status = EXECUTION_STATE_INPROGRESS
            siemplify.LOGGER.info(u'Script Name: {} | {}'.format(SCRIPT_NAME, output_message))

    except SlackManagerException as e:
        output_message = u'An error occurred when trying to get message replies: {}'.format(e)
        result = 'false'
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(u'Script Name: {} | {}'.format(SCRIPT_NAME, output_message))
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u'Status: {}'.format(status))
    siemplify.LOGGER.info(u'Result: {}'.format(result))
    siemplify.LOGGER.info(u'Output Message: {}'.format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
