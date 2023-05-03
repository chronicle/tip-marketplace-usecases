from datamodels import *


class SentinelOneV2Parser(object):
    @staticmethod
    def build_siemplify_system_status_obj(system_status_data):
        return SystemStatus(
            raw_data=system_status_data,
            is_ok=system_status_data.get('data', {}).get('health', '').lower() == u'ok',
            errors=system_status_data.get('errors', [])
        )

    @staticmethod
    def build_siemplify_agent_obj(agent_data):
        interfaces = [SentinelOneV2Parser.build_siemplify_agent_inteface_obj(interface) for interface in
                      agent_data.get("networkInterfaces", [])]
        return Agent(
            raw_data=agent_data,
            interfaces = interfaces,
            **agent_data
        )

    @staticmethod
    def build_siemplify_agent_inteface_obj(interface_data):
        return AgentInterface(
            raw_data=interface_data,
            **interface_data
        )

    @staticmethod
    def build_siemplify_group_obj(group_data):
        return Group(
            raw_data=group_data,
            **group_data
        )

    @staticmethod
    def build_siemplify_event_obj(event_data):
        return Event(
            raw_data=event_data,
            **event_data
        )

    @staticmethod
    def build_siemplify_process_event_obj(event_data):
        return ProcessEvent(
            raw_data=event_data,
            **event_data
        )

    @staticmethod
    def build_siemplify_file_event_obj(event_data):
        return FileEvent(
            raw_data=event_data,
            **event_data
        )

    @staticmethod
    def build_siemplify_indicator_event_obj(event_data):
        return IndicatorEvent(
            raw_data=event_data,
            **event_data
        )

    @staticmethod
    def build_siemplify_dns_event_obj(event_data):
        return DNSEvent(
            raw_data=event_data,
            **event_data
        )

    @staticmethod
    def build_siemplify_network_actions_event_obj(event_data):
        return NetworkActionsEvent(
            raw_data=event_data,
            **event_data
        )

    @staticmethod
    def build_siemplify_url_event_obj(event_data):
        return URLEvent(
            raw_data=event_data,
            **event_data
        )

    @staticmethod
    def build_siemplify_registry_event_obj(event_data):
        return RegistryEvent(
            raw_data=event_data,
            **event_data
        )

    @staticmethod
    def build_siemplify_scheduled_task_event_obj(event_data):
        return ScheduledTaskEvent(
            raw_data=event_data,
            **event_data
        )