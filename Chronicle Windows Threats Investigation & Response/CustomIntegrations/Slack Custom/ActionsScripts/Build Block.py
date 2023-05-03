from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
import re
import json
import logging
import os
import json
import ast


SCRIPT_NAME = u'Slack Custom - Build Block'
PROVIDER_NAME = u'Slack Custom'
QUESTION_BLOCK = """{{"type": "divider"}},{{"type": "section","text": {{"type": "mrkdwn","text": "{question}"}}}}"""
BUTTON_BLOCK = """{{"type": "button","text": {{"type": "plain_text","text": "{answer}"}},"value": "blockuser","url": "{url_}"}}"""

@output_handler
def main():

    json_result = {}
    status = EXECUTION_STATE_FAILED
    output_message = ''
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    api_token = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="ApiToken",
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
    )
    hook_url = extract_action_param(
        siemplify,
        param_name="WebHook Url",
        is_mandatory=True,
        print_value=False,
    )

    question = extract_action_param(
        siemplify,
        param_name="Question",
        is_mandatory=True,
        print_value=False,
    )

    answers = extract_action_param(
        siemplify,
        param_name="Answers Buttons",
        is_mandatory=True,
        print_value=False,
    )

    
    view_case_url= extract_action_param(
        siemplify,
        param_name="View Case In Siemplify URL",
        is_mandatory=True,
        print_value=False,
    )
    case_id= extract_action_param(
        siemplify,
        param_name="Case Id",
        is_mandatory=True,
        print_value=False,
    )
    
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    
    answers_list = answers.split(',')
    payload = '['
    payload += QUESTION_BLOCK.format(question=question.encode('utf-8').strip())
    payload += """,
        {
            "type": "actions",
            "elements": ["""
    view_case_url += '/#/main/cases/dynamic-view/'
    view_case_url += case_id
    for i in answers_list:
        if i!="":
            payload += BUTTON_BLOCK.format(answer = i, url_ = hook_url+"?Answer="+i.replace(' ','_'))
            payload+=',\n'
    if view_case_url != 'None':
        payload += BUTTON_BLOCK.format(answer='View Case In Siemplify', url_=view_case_url)
        payload+=',\n'
    payload += ']}]'
    try:
        siemplify.LOGGER.info("Try - Evaluating payload")
        payload = ast.literal_eval(question)
        siemplify.LOGGER.info("Success - Evaluating payload")
        status = EXECUTION_STATE_COMPLETED
    except Exception as e:
        siemplify.LOGGER.error("Error message: {}".format(e))
        
    status = EXECUTION_STATE_COMPLETED
    siemplify.result.add_result_json({'result':payload})
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    result_value = True
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()