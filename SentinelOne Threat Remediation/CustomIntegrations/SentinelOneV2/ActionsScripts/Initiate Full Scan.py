from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SentinelOneV2Manager import SentinelOneV2Manager, SentinelOneV2NotFoundError
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import flat_dict_to_csv
from TIPCommon import extract_configuration_param


# Consts.
INTEGRATION_NAME = u'SentinelOneV2'
SCRIPT_NAME = u'Initiate Full Scan'
ADDRESS = EntityTypes.ADDRESS
HOSTNAME = EntityTypes.HOSTNAME


@output_handler
def main():
    # Define variables.
    entities_successed = []
    errors_dict = {}
    result_value = False
    # Configuration.
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Root",
                                           is_mandatory=True, input_type=unicode)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Token",
                                            is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    sentinel_one_manager = SentinelOneV2Manager(api_root, api_token, verify_ssl)

    # Get scope entities.
    scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == ADDRESS or
                      entity.entity_type == HOSTNAME]

    # Initiate full scan.
    for entity in scope_entities:
        try:
            siemplify.LOGGER.info(u"Processing entity {}".format(entity.identifier))

            # Get endpoint agent id.
            if entity.entity_type == EntityTypes.HOSTNAME:
                try:
                    siemplify.LOGGER.info(u"Fetching agent for hostname {}".format(entity.identifier))
                    agent = sentinel_one_manager.get_agent_by_hostname(entity.identifier)
                except SentinelOneV2NotFoundError as e:
                    # Agent was not found in SentinelOne - skip entity
                    siemplify.LOGGER.info(unicode(e))
                    siemplify.LOGGER.info(u"Skipping entity {}".format(entity.identifier))
                    continue

            elif entity.entity_type == EntityTypes.ADDRESS:
                try:
                    siemplify.LOGGER.info(u"Fetching agent for address {}".format(entity.identifier))
                    agent = sentinel_one_manager.get_agent_by_ip(entity.identifier)
                except SentinelOneV2NotFoundError as e:
                    # Agent was not found in SentinelOne - skip entity
                    siemplify.LOGGER.info(unicode(e))
                    siemplify.LOGGER.info(u"Skipping entity {}".format(entity.identifier))
                    continue

            else:
                siemplify.LOGGER.info(u"Entity {} is of unsupported type.".format(entity.identifier))
                continue

            agent_uuid = agent.uuid

            if agent_uuid:
                siemplify.LOGGER.info(u"Found agent {} for entity {}".format(agent_uuid, entity.identifier))
                siemplify.LOGGER.info(u"Initiating full scan for agent {}".format(agent_uuid))
                scan_status = sentinel_one_manager.initiate_full_scan_by_uuid(agent_uuid)

                if scan_status:
                    result_value = True
                    entities_successed.append(entity)
            else:
                siemplify.LOGGER.error(u'Error: Not found uuid for entity "{0}"'.format(entity.identifier))
        except Exception as err:
            siemplify.LOGGER.error(err.message)
            siemplify.LOGGER.exception(err)
            errors_dict[entity.identifier] = unicode(err.message)

    # Form output message.
    if entities_successed:
        output_message = u'Full disk initiated for: {0}'.format(u",".join([entity.identifier for entity in
                                                                         entities_successed]))
    else:
        output_message = u'No target entities were scanned.'

    # If were errors present them as a table.
    if errors_dict:
        # Produce error CSV.
        errors_csv = flat_dict_to_csv(errors_dict)
        # Draw table.
        siemplify.result.add_data_table(u'Unsuccessful Attempts', errors_csv)

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
