from WebhookManager import WebhookManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT

# Consts:
INTEGRATION_NAME = "Webhook"
SCRIPT_NAME = "Create Token"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("================= Main - Param Init =================")

    conf = siemplify.get_configuration(INTEGRATION_NAME)
    baseUrl = conf.get("URL")
    
    # INIT ACTION PARAMETERS:
    def_content = siemplify.extract_action_param(param_name="Default Content")
    def_content_type = siemplify.extract_action_param(param_name="Default Content Type").strip()
    timeout = siemplify.extract_action_param(param_name="Timeout")

    siemplify.LOGGER.info("================= Main - Started ====================")
    
    # Init result json:
    res_json = {}
    # Init result values:
    status = EXECUTION_STATE_FAILED
    output_message = "Something went wrong. " 
    result_value = False

    # Create manager instance for methods:
    webhookManager = WebhookManager(baseUrl)

    try:
        # Create token:
        res_json = webhookManager.create_token(def_content ,def_content_type ,timeout)
        res_json["webhookURL"] = f'{baseUrl}/{res_json.get("uuid")}'
        status = EXECUTION_STATE_COMPLETED
        output_message = f'URL Created: {res_json.get("webhookURL")}'
        result_value = True
        
    except Exception as e:
        siemplify.LOGGER.error(e)
        output_message += "Error: " + str(e)
    
    finally:
        siemplify.LOGGER.info("\n  status: {}\n  result_value: {}\n  output_message: {}".format(status,result_value, output_message))
        siemplify.result.add_result_json(res_json)
        siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
