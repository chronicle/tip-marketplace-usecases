from WebhookManager import WebhookManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT

# Consts:
INTEGRATION_NAME = "Webhook"
SCRIPT_NAME = "Ping"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("================= Main - Param Init =================")
    
    # Init integration params:
    conf = siemplify.get_configuration(INTEGRATION_NAME)
    baseUrl = conf.get("URL")

    # Create manager instance for methods:
    webhookManager = WebhookManager(baseUrl)
    
    # Init result values:
    status = EXECUTION_STATE_FAILED
    output_message = "The connection failed."
    return_value = False
    
    try:
        response = webhookManager.test_connectivity()
        return_value = True
        output_message = f'Connected successfully to <{baseUrl}>'
        
    except:
        siemplify.LOGGER.error(e)
        output_message += " Error: " + str(e)
    
    finally:
        siemplify.LOGGER.info("----------------- Main - Finished -----------------")
        siemplify.LOGGER.info("status: {}\nresult_value: {}\noutput_message: {}".format(status, return_value, output_message))
        siemplify.end(output_message, return_value, status)


if __name__ == "__main__":
    main()

