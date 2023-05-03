from WebhookManager import WebhookManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT

# Consts:
INTEGRATION_NAME = "Webhook"
SCRIPT_NAME = "Delete Token"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("================= Main - Param Init =================")
    
    # Extract Integration params:
    conf = siemplify.get_configuration(INTEGRATION_NAME)
    baseUrl = conf.get("URL")
    
    # INIT ACTION PARAMETERS:
    token_id = siemplify.extract_action_param(param_name="Token ID").strip()
    
    # Init result values
    status = EXECUTION_STATE_FAILED
    output_message = f'Something went wrong deleting token <{token_id}>.'
    result_value = False
    
    # Create manager instance for methods:
    webhookManager = WebhookManager(baseUrl)
    
    try:
        # Delete token:
        result_status = webhookManager.delete_token(token_id)
        status = EXECUTION_STATE_COMPLETED
        output_message = f'Token <{token_id}> was successfully deleted.'
        output_message += f' Deletion status: {result_status}'
        result_value = True
        
    except Exception as e:
        siemplify.LOGGER.error(e)
        output_message += " Error: " + str(e)
        
    finally:
        siemplify.LOGGER.info("\n  status: {}\n  result_value: {}\n  output_message: {}".format(status,result_value, output_message))
        siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
