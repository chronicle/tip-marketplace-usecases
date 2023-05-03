from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT
from TIPCommon import extract_configuration_param, extract_action_param
from SlackAdditionalManager import SlackAdditionalManager, SlackManagerException, UserNotFoundException
import json, ast
PROVIDER_NAME = u'Slack Custom'

@output_handler
def main():
    siemplify = SiemplifyAction()
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

    message_type = extract_action_param(
        siemplify,
        param_name="Message Type",
        is_mandatory=True,
        print_value=True,
        input_type=unicode
    )
    recipient_type = extract_action_param(
        siemplify,
        param_name="Recipient Type",
        is_mandatory=True,
        print_value=True,
        input_type=unicode
    )
    message = extract_action_param(
        siemplify,
        param_name="Message",
        is_mandatory=True,
        print_value=True,
        input_type=unicode
    )
    recipient = extract_action_param(
        siemplify,
        param_name="Recipient",
        is_mandatory=True,
        print_value=True,
        input_type=unicode
    )

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    result_value = ''
    response = ''
    try:
        user_id = ''
        slack_manager = SlackAdditionalManager(api_token, verify_ssl)
        users = list(slack_manager.list_users())
        if recipient_type == 'Full name':
            for user in users:
                if recipient.lower() in user.to_json()['Profile']['Real Name'].lower():
                    user_id = user.to_json()['ID']
        elif recipient_type == 'Email':
            for user in users:
                if user.to_json()['Profile']['Email']:
                    if recipient.lower() in user.to_json()['Profile']['Email'].lower():
                        user_id = user.to_json()['ID']
        elif recipient_type == 'Id':
            user_id = recipient
        if message_type == 'Text':
            response = slack_manager.send_message(channel=user_id,message=message)
        elif message_type == 'Block':
            payload = "";
            payload = ast.literal_eval(message)
            siemplify.LOGGER.info("Done evaluating payload")
            response = slack_manager.send_block_message(channel=user_id,message=payload)
    
        
        output_message = u'Successfully sent message'
        status = EXECUTION_STATE_COMPLETED
        result_value=True
        siemplify.result.add_result_json(response)
        
        
    except Exception as e:
        output_message = u'An error occurred when trying to receive user with id {}: {}'.format(user_id, e)
        result = 'false'
        status = EXECUTION_STATE_FAILED
        siemplify.result.add_result_json({"ok":False})
        siemplify.LOGGER.exception(e)
    
    siemplify.LOGGER.info("\n  status: {}\n  result_value: {}\n  output_message: {}".format(status,result_value, output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
