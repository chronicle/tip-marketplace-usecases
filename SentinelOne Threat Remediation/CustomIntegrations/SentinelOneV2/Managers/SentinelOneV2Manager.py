# ==============================================================================
# title           :SentinelOneV2Manager.py
# description     :SentinelOne integration logic.
# author          :victor@siemplify.co
# date            :21-3-18
# python_version  :2.7
# product_version : Eiffel
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
import requests
import urlparse
import copy
import datetime
from SentinelOneV2Parser import SentinelOneV2Parser
from datamodels import COMPLETED_QUERY_STATUSES, FAILED_QUERY_STATUSES

# =====================================
#               CONSTS                #
# =====================================
MAXIMUM_EVENTS_ALLOWED = 1000
DEFAULT_PAGE_SIZE = 25
# Time Formats.
FETCH_EVENT_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'
FETCH_THREATS_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.000000Z'

# URLs.
GET_AGENTS_URL = '/web/api/v2.0/agents'
GET_AGENTS_COUNT_URL = '/web/api/v2.0/agents/count'
DISCONNECT_AGENTS_FROM_NETWORK_URL = '/web/api/v2.0/agents/actions/disconnect'
GET_AGENT_APPLICATIONS_URL = '/web/api/v2.0/agents/applications'
GET_EVENTS_FOR_AGENT_BY_TIME_URL = '/web/api/v2.0/ioc/events/process'  # {0} - Agent UUID.
GET_HASH_REPUTATION_URL = '/web/api/v2.0/hashes/{0}/reputation'  # {0} - File Hash(SHA1).
GET_PROCESSES_FOR_AGENT_URL = '/web/api/v2.0/agents/processes'
GET_SYSTEM_STATUS_URL = '/web/api/v2.0/system/status'
GET_DB_SYSTEM_STATUS_URL = '/web/api/v2.0/system/status/db'
GET_CACHE_SERVER_SYSTEM_STATUS_URL = '/web/api/v2.0/system/status/cache'
GET_SYSTEM_VERSION_URL = '/web/api/v2.0/system/info'
INITIATE_FULL_SCAN_URL = '/web/api/v2.0/agents/actions/initiate-scan'
CONNECT_AGENT_TO_NETWORK_URL = '/web/api/v2.0/agents/actions/connect'
CREATE_PATH_EXCLUSION_URL = '/web/api/v2.0/exclusions'
GET_THREATS_URL = '/web/api/v2.0/threats'
QUERY_URL = '/web/api/v2.0/private/dv/init-private-streaming-query'
QUERY_STATUS_URL = '/web/api/v2.0/private/dv/query-streaming-status'
GET_PROCESS_EVENTS_URL = '/web/api/v2.0/dv/events/process'
GET_FILE_EVENTS_URL = '/web/api/v2.0/dv/events/file'
GET_INDICATOR_EVENTS_URL = '/web/api/v2.0/dv/events/indicators'
GET_DNS_EVENTS_URL = '/web/api/v2.0/dv/events/dns'
GET_NETWORK_ACTIONS_EVENTS_URL = '/web/api/v2.0/dv/events/ip'
GET_URL_EVENTS_URL = '/web/api/v2.0/dv/events/url'
GET_REGISTRY_EVENTS_URL = '/web/api/v2.0/dv/events/registry'
GET_SCHEDULED_TASK_EVENTS_URL = '/web/api/v2.0/dv/events/scheduled_task'
GET_ALL_EVENTS_URL = '/web/api/v2.0/private/dv/all-events'

# Added by Daniel
GET_ACTIVITIES_URL = 'web/api/v2.0/activities'
GET_ACTIVITY_TYPES_URL = '/web/api/v2.0/activities/types'
FETCH_FILES_FROM_AGENTS_URL = '/web/api/v2.0/agents/{0}/actions/fetch-files'
FETCH_FILES_FROM_THREAT_URL = '/web/api/v2.0/threats/fetch-file'
FETCH_LOGS_FROM_AGENT_URL = '/web/api/v2.0/agents/actions/fetch-logs'
GET_AGENT_INSTALLED_APPLICATIONS = '/web/api/v2.0/installed-applications'
GET_APPLCATION_CVE_URL = '/web/api/v2.0/private/installed-applications/{0}/cves'
GET_APPLICATION_FORENSIC_DETAILS_URL = '/web/api/v2.0/applications/{}/forensics/details'
GET_AVAILABLE_AGENT_ACTIONS_URL = '/web/api/v2.0/private/agents/available-actions'
GET_AVAILABLE_AGENT_COMMANDS_URL = '/web/api/v2.0/private/commands'
GET_EVENTS_BY_QUERY_URL = '/web/api/v2.0/dv/events'
GET_GROUPS_URL = '/web/api/v2.0/groups'
GET_GROUP_BY_ID_URL = '/web/api/v2.0/groups/{0}'
MOVE_AGENT_TO_GROUP_URL = '/web/api/v2.0/groups/{0}/move-agents'
GET_POLICY_URL = '/web/api/v2.0/private/policy'
AGENT_ACTION_URL = '/web/api/v2.0/agents/actions/{}'
ABORT_FULL_SCAN_URL = '/web/api/v2.0/agents/actions/abort-scan'
INITIATE_REBOOT_URL = '/web/api/v2.0/agents/actions/restart-machine'
DECOMMISSION_AGENT_URL = '/web/api/v2.0/agents/actions/decommission'
CREATE_HASH_EXCLUSION_URL = '/web/api/v2.0/restrictions'
GET_THREAT_FORENSIC_DETAILS_URL = '/web/api/v2.0/threats/{}/forensics/details'
GET_THREAT_ACTIONS_URL = '/web/api/v2.1/private/threats/available-actions'  # Obsereved in DeveloperOptions over the UI. Changed version to 2.1 from 2.0
CREATE_IOC_THREAT_URL = '/web/api/v2.0/private/threats/ioc-create-threats'
MITIGATE_THREAT_URL = '/web/api/v2.0/threats/mitigate/{0}'
MARK_THREAT_URL = '/web/api/v2.0/threats/{0}'
RESOLVE_THREAT_URL = '/web/api/v2.0/threats/mark-as-resolved'

# Payloads.
ACTIVITY_PAYLOAD = {
    "skipCount": False,
    "countOnly": False,
    "sortOrder": "desc",
    "limit": 1,
    "includeHidden": False
}

LOGIN_PAYLOAD = {
    "username": "",
    "rememberMe": "true",
    "password": ""
}

DISCONNECT_AGENTS_FROM_NETWORK_PAYLOAD = {
    "filter": {
        "ids": []
    },
    "data": {}
}

INITIATE_FULL_SCAN_PAYLOAD = RECONNECT_AGENT_TO_NETWORK_PAYLOAD = {
    "filter": {
        "uuid": ""
    },
    "data": {}
}

AGENT_ACTIONS_PAYLOAD = {
    "filter": {},
    "data": {}
}

FETCH_FILES_FROM_AGENT_PAYLOAD = {
    "data": {
        "files": [],
        "password": ""
    }
}

FETCH_FILE_FROM_THREAT_PAYLOAD = {
    "filter": {
        "ids": []
    },
    "data": {
        "password": ""
    }
}

GET_POLICY_PAYLOAD = {
    "siteIds": "",
    "groupIds": "",
    "accountIds": "",
    "tenant": "false"
}

CREATE_PATH_EXCLUSION_PAYLOAD = CREATE_HASH_EXCLUSION_PAYLOAD = {
    "filter": {},
    "data": {
        "value": "",
        "osType": "windows",  # Cam be:  windows, windows_legacy, macos or linux
        "type": "path",
        "description": "Created by Siemplify."
    }
}

GET_AGENT_APPLICATIONS_PARAMS = GET_AGENT_PROCESSES_PARAMS = {
    "ids": ""
}

GET_INSTALLED_APPLICATIONS_PARAMS = {
    "agentUuid__contains": "",
    "riskLevels": "",
    "agentIsDecommissioned": False,
    "limit": "",
    "sortOrder": "desc",
    "sortBy": "",
    "types": "",
    "name__contains": "",
    "installedAt__between": ""
}

GET_EVENTS_BY_DATE_PARAMS = {
    "query": "",
    "fromDate": "2017-11-06T19:11:00.000Z",
    "toDate": "2017-11-07T19:11:00.000Z",
    "limit": 10
}

GET_THREATS_PARAMS = {
    "resolved": False,
    "createdAt__gt": "2018-02-27T04:49:26.257525Z"

}

MARK_THREAT_RESOLVED_PARAMS = MITIGATE_THREAT_PARAMS = {
    "filter": {
        "ids": []
    }
}

MARK_THREAT_RESOLVED_ANNOTATE_PARAMS = {
    "filter": {
        "ids": []
    },
    "data": {
        "annotation": ""
    }
}

ANNOTATE_THREAT_PARAMS = {
    "data": {
        "annotation": ""
    }
}

GET_SYSTEM_INFO_PARAMS = {
    "uuids": "",
}

# Headers.
HEADERS = {
    "Content-Type": "application/json"
}


# =====================================
#              CLASSES                #
# =====================================
class SentinelOneV2ManagerError(Exception):
    """
    Custom Error.
    """
    pass


class SentinelOneV2NotFoundError(Exception):
    """
    Not Found Error.
    """
    pass


class SentinelOneV2ApiLimitError(Exception):
    """
    API Limit Error.
    """
    pass


class SentinelOneV2Manager(object):
    def __init__(self, api_root, api_token, verify_ssl=False, logger=None):
        """
        :param api_root: API root URL.
        :param username: SentinelOne Username
        :param password: SentinelOne Password
        """
        self.api_root = api_root if api_root[-1:] == u'/' else api_root + u'/'
        self.session = requests.session()
        self.session.verify = verify_ssl
        self.session.headers = copy.deepcopy(HEADERS)
        self.session.headers['Authorization'] = u"ApiToken {}".format(api_token)
        self.parser = SentinelOneV2Parser()
        self.logger = logger

    def test_connectivity(self):
        """
        Test connectivity to SentinelOne V2
        :return: {bool} True if successful, exception otherwise
        """
        try:
            request_url = urlparse.urljoin(self.api_root, GET_AGENTS_COUNT_URL)
            response = self.session.get(request_url)
            self.validate_response(response)
            return True
        except Exception as e:
            raise SentinelOneV2ManagerError(u"Unable to connect to SentinelOne V2. Error: {}".format(e))

    @staticmethod
    def validate_response(response, error_msg=u"An error occurred"):
        """
        Validate response
        :param response: {requests.Response} The response to validate
        :param error_msg: {unicode} Default message to display on error
        """
        if response.status_code == 401:
            raise SentinelOneV2ManagerError(u"API token is invalid or expired. Immediately update it!")

        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            raise SentinelOneV2ManagerError(
                u"{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=response.content)
            )

    def get_avaliable_actions(self, agent_uuid):
        request_url = urlparse.urljoin(self.api_root, GET_AVAILABLE_AGENT_ACTIONS_URL)
        payload = {"uuid": agent_uuid}
        response = self.session.get(request_url, json=payload)
        self.validate_response(response)
        return response.json().get('data', {})

    # New Action
    def get_available_commands(self, agent_uuid):
        request_url = urlparse.urljoin(self.api_root, GET_AVAILABLE_AGENT_COMMANDS_URL)
        payload = {"uuid": agent_uuid}
        response = self.session.get(request_url, json=payload)
        self.validate_response(response)
        return response.json().get('data', {})

    def get_activity_types(self):
        request_url = urlparse.urljoin(self.api_root, GET_ACTIVITY_TYPES_URL)
        response = self.session.get(request_url)
        self.validate_response(response)
        return response.json().get('data', [])

    def get_activity(self, threat_id=None, agent_id=None, site_ids=None, activity_type=None, limit=1):
        params = copy.deepcopy(ACTIVITY_PAYLOAD)
        activity_information = []

        if agent_id:
            params.update({"agentIds": agent_id})

        if threat_id:
            params.update({"threatIds": threat_id})

        if site_ids:
            params.update({"siteIds": site_ids})

        if activity_type:
            params['activityTypes'] = activity_type

        if limit:
            params['limit'] = limit

        request_url = urlparse.urljoin(self.api_root, GET_ACTIVITIES_URL)
        response = self.session.get(request_url, params=params)
        self.validate_response(response)
        
        activities = response.json().get('data', [])

        for activity in activities:
            activity_info = activity.get('data', [])
            activity_info['primary_description'] = activity.get('primaryDescription')
            activity_info['activity_type'] = activity.get('activityType')
            activity_information.append(activity_info)
            
        return activity_information

    def get_agent_by_hostname(self, hostname):
        """
        Get agent by hostname
        :param hostname: {unicode} Hostname (computer name) to filter agents by
        :return: {Agent} Matching agent
        """
        found_endpoint = False
        request_url = urlparse.urljoin(self.api_root, GET_AGENTS_URL)
        params = {
            u"computerName__contains": hostname
        }
        agents = self._paginate_results(
            method=u"GET",
            url=request_url,
            params=params,
            err_msg=u"Unable to get agents with hostname {}".format(hostname)
        )

        agents = [self.parser.build_siemplify_agent_obj(agent) for agent in agents]

        for agent in agents:
            if hostname.lower() == (agent.computer_name).lower():
                found_endpoint = True
                return agent

        if not found_endpoint:
            raise SentinelOneV2NotFoundError(u"Agent with hostname {} was not found".format(hostname))

        return agents[0]

    def get_agent_by_id(self, agent_id):
        """
        Get agent by agent_id
        :param agent_id: {unicode} The UUID of the agent
        :return: {Agent} Matching agent
        """
        request_url = urlparse.urljoin(self.api_root, GET_AGENTS_URL)
        params = {
            u"ids": agent_id
        }
        agents = self._paginate_results(
            method=u"GET",
            url=request_url,
            params=params,
            err_msg=u"Unable to get agents with uuid {}".format(agent_id)
        )

        agents = [self.parser.build_siemplify_agent_obj(agent) for agent in agents]

        if not agents:
            raise SentinelOneV2NotFoundError(u"Agent with ID {} was not found".format(agent_id))

        return agents[0]

    def get_agent_by_uuid(self, agent_uuid):
        """
        Get agent by agent_uuid
        :param agent_uuid: {unicode} The UUID of the agent
        :return: {Agent} Matching agent
        """
        request_url = urlparse.urljoin(self.api_root, GET_AGENTS_URL)
        params = {
            u"uuids": agent_uuid
        }
        agents = self._paginate_results(
            method=u"GET",
            url=request_url,
            params=params,
            err_msg=u"Unable to get agents with uuid {}".format(agent_uuid)
        )

        agents = [self.parser.build_siemplify_agent_obj(agent) for agent in agents]

        if not agents:
            raise SentinelOneV2NotFoundError(u"Agent with UUID {} was not found".format(agent_uuid))

        return agents[0]

    def get_agent_by_ip(self, ip_address):
        """
        Get agents by IP address
        :param ip_address: {unicode} IP to filter agents by
        :return: {[Agent]} List of matching agents
        """
        request_url = urlparse.urljoin(self.api_root, GET_AGENTS_URL)
        params = {
            u"limit": DEFAULT_PAGE_SIZE
        }
        response = self.session.get(request_url, params=params)
        self.validate_response(response, u"Unable to list agents")
        agents = [self.parser.build_siemplify_agent_obj(agent) for agent in response.json().get("data", [])]
        external_ip = []
        while True:
            # Search for matching agent in found agents
            for agent in agents:
                for interface in agent.interfaces:
                    if ip_address in interface.inet:
                        return agent

            # Agent with matching IP was not found yet - paginate some more
            if not response.json().get(u"pagination", {}).get(u"nextCursor"):
                # No more pages
                break

            params.update(
                {
                    u"cursor": response.json().get(u"pagination", {}).get(u"nextCursor")
                }
            )

            # Get next page of agents
            response = self.session.get(request_url, params=params)
            self.validate_response(response, u"Unable to list agents")
            agents = [self.parser.build_siemplify_agent_obj(agent) for agent in response.json().get(u"data", [])]

        if external_ip:
            return external_ip

        raise SentinelOneV2NotFoundError(u"Agent with IP {} was not found".format(ip_address))

    def disconnect_agent_from_network(self, agent_id):
        """
        Disconnect agent from the network.
        :param agent_id: {string} Agent ID.
        :return: {bool} True if succeed.
        """
        payload = copy.deepcopy(DISCONNECT_AGENTS_FROM_NETWORK_PAYLOAD)
        payload['filter']['ids'].append(agent_id)

        request_url = urlparse.urljoin(self.api_root, DISCONNECT_AGENTS_FROM_NETWORK_URL)
        response = self.session.post(request_url, json=payload)
        self.validate_response(response)

        return True

    def reconnect_agent_to_network(self, agent_uuid):
        """
        Connect endpoint to the network.
        :param agent_uuid: {string} endpoint agent uuid
        :return: {bool} is success
        """
        payload = copy.deepcopy(RECONNECT_AGENT_TO_NETWORK_PAYLOAD)
        payload['filter']['uuid'] = agent_uuid
        request_url = urlparse.urljoin(self.api_root, CONNECT_AGENT_TO_NETWORK_URL.format(agent_uuid))
        response = self.session.post(request_url, json=payload)
        self.validate_response(response)
        return True

    def fetch_files_from_agent(self, agent_id, path, file_pass="SiemplifyP@ss123"):
        payload = copy.deepcopy(FETCH_FILES_FROM_AGENT_PAYLOAD)
        payload['data']['files'] = [path]
        payload['data']['password'] = file_pass
        request_url = urlparse.urljoin(self.api_root, FETCH_FILES_FROM_AGENTS_URL.format(agent_id))
        response = self.session.post(request_url, json=payload)
        self.validate_response(response)
        return True

    def move_agent_to_group(self, agent_id, group_id):
        request_url = urlparse.urljoin(self.api_root, MOVE_AGENT_TO_GROUP_URL.format(group_id))
        payload = {"filter": {"agentIds": [agent_id]}}
        response = self.session.put(request_url, json=payload)
        self.validate_response(response)
        return True

    def run_agent_action(self, agent_uuid=None, agent_id=None, action_name=None):
        """
        Initiate full endpoint scan.
        :param agent_uuid: {string} Agent's uuid.
        :param action_name: {string} Action Name
        :return: {bool} is succeed.
        """
        payload = copy.deepcopy(AGENT_ACTIONS_PAYLOAD)

        if agent_uuid:
            payload['filter']['uuid'] = agent_uuid
        else:
            payload['filter']['ids'] = agent_id

        request_url = urlparse.urljoin(self.api_root, AGENT_ACTION_URL.format(action_name))
        response = self.session.post(request_url, json=payload)
        self.validate_response(response)
        return response.json()

    def get_agent_status(self, agent_uuid):
        """
        Get agent's status.
        :param agent_uuid: endpoint agent uuid {string}
        :return: endpoint system information {dict}
        """
        agent = self.get_agent_by_uuid(agent_uuid)
        return agent.is_active

    def get_applications_from_endpoint(self, agent_id):
        """
        Get applications list for an agent.
        :param agent_id: {string} Agent ID.
        :return: {list} list of application objects.
        """
        params = copy.deepcopy(GET_AGENT_APPLICATIONS_PARAMS)
        params['ids'] = agent_id
        request_url = urlparse.urljoin(self.api_root, GET_AGENT_APPLICATIONS_URL)
        response = self.session.get(request_url, params=params)
        self.validate_response(response)
        return response.json().get('data', [])

    def get_installed_applications(self, agent_id=None, app_name=None, risk_level=None, limit=None, sort_by=None,
                                   types=None, installed_between=None):
        payload = copy.deepcopy(GET_INSTALLED_APPLICATIONS_PARAMS)
        request_url = urlparse.urljoin(self.api_root, GET_AGENT_INSTALLED_APPLICATIONS)
        payload["agentUuid__contains"] = agent_id
        payload["riskLevels"] = risk_level
        payload["limit"] = limit
        payload["sortBy"] = sort_by
        payload["types"] = types
        payload["name__contains"] = app_name
        payload["installedAt__between"] = installed_between

        # remove none items
        url_params = {k: v for k, v in payload.items() if v is not None}

        response = self.session.get(request_url, params=url_params)
        self.validate_response(response)
        return response.json().get('data', {})

    def get_application_cve(self, app_id):
        request_url = urlparse.urljoin(self.api_root, GET_APPLCATION_CVE_URL.format(app_id))
        response = self.session.get(request_url)
        self.validate_response(response)
        return response.json().get('data', []).get('cves')

    def get_applications_forensic_information(self, app_id):
        request_url = urlparse.urljoin(self.api_root, GET_APPLICATION_FORENSIC_DETAILS_URL.format(app_id))
        response = self.session.get(request_url)
        self.validate_response(response)
        return response.json().get('data', []).get('result')

    def get_hash_reputation(self, file_hash):
        """
        Get file hash reputation.
        :param file_hash: {string} file hash.
        :return: {string} file hash reputation data.
        """
        request_url = urlparse.urljoin(self.api_root, GET_HASH_REPUTATION_URL.format(file_hash))
        response = self.session.get(request_url)
        self.validate_response(response)
        return response.json().get('data', {}).get('rank')

    def get_agent_processes_list(self, agent_id):
        """
        :param agent_id: endpoint agent id {string}
        :return: {list}
        """
        params = copy.deepcopy(GET_AGENT_PROCESSES_PARAMS)
        params['ids'] = agent_id
        request_url = urlparse.urljoin(self.api_root, GET_PROCESSES_FOR_AGENT_URL)
        response = self.session.get(request_url, params=params)
        self.validate_response(response)
        return response.json().get('data', [])

    def get_group(self, group_name=None, search=False):
        request_url = urlparse.urljoin(self.api_root, GET_GROUPS_URL)

        if group_name:
            if search:
                payload = {"query": group_name}
            else:
                payload = {"name": group_name}
            response = self.session.get(request_url, params=payload)
        else:
            response = self.session.get(request_url)

        self.validate_response(response)
        groups = response.json().get('data', {})
        group_data = [self.parser.build_siemplify_group_obj(group) for group in groups]
        return group_data

    def get_group_by_id(self, group_id):
        request_url = urlparse.urljoin(self.api_root, GET_GROUP_BY_ID_URL.format(group_id))
        response = self.session.get(request_url)
        self.validate_response(response)
        return response.json().get('data', {})

    def get_policy(self, site_ids=None, group_ids=None, account_ids=None, tenant="false"):
        """
        Get policy data.
        :return: {dict} policy data.
        """
        payload = copy.deepcopy(GET_POLICY_PAYLOAD)
        if site_ids:
            payload['siteIds'] = site_ids

        if group_ids:
            payload['groupIds'] = group_ids

        if account_ids:
            payload['accountIds'] = account_ids

        if tenant:
            payload['tenant'] = tenant

        request_url = urlparse.urljoin(self.api_root, GET_POLICY_URL)
        response = self.session.get(request_url, json=payload)
        self.validate_response(response)
        return response.json().get('data', {})

    def get_system_status(self):
        """
        Returns current system health status.
        :return: {SystemStatus} The system status obj
        """
        request_url = urlparse.urljoin(self.api_root, GET_SYSTEM_STATUS_URL)
        response = self.session.get(request_url)
        self.validate_response(response)
        return self.parser.build_siemplify_system_status_obj(response.json())

    def get_db_system_status(self):
        """
        Returns current DB system health status.
        :return: {SystemStatus} The system status obj
        """
        request_url = urlparse.urljoin(self.api_root, GET_DB_SYSTEM_STATUS_URL)
        response = self.session.get(request_url)
        self.validate_response(response)
        return self.parser.build_siemplify_system_status_obj(response.json())

    def get_cache_server_system_status(self):
        """
        Returns current cache server system health status.
        :return: {SystemStatus} The system status obj
        """
        request_url = urlparse.urljoin(self.api_root, GET_CACHE_SERVER_SYSTEM_STATUS_URL)
        response = self.session.get(request_url)
        self.validate_response(response)
        return self.parser.build_siemplify_system_status_obj(response.json())

    def get_system_version(self):
        """
        Returns current system version.
        :return: system version information {dict}
        """
        request_url = urlparse.urljoin(self.api_root, GET_SYSTEM_VERSION_URL)
        response = self.session.get(request_url)
        self.validate_response(response)
        return response.json().get('data', {})

    def initiate_full_scan_by_uuid(self, agent_uuid):
        """
        Initiate full endpoint scan.
        :param agent_uuid: {string} Agent's uuid.
        :return: {bool} is succeed.
        """
        payload = copy.deepcopy(INITIATE_FULL_SCAN_PAYLOAD)
        payload['filter']['uuid'] = agent_uuid
        request_url = urlparse.urljoin(self.api_root, INITIATE_FULL_SCAN_URL)
        response = self.session.post(request_url, json=payload)
        self.validate_response(response)
        return True

    def connect_agent_to_network(self, agent_uuid):
        """
        Connect endpoint to the network.
        :param agent_uuid: {string} endpoint agent uuid
        :return: {bool} is success
        """
        payload = copy.deepcopy(RECONNECT_AGENT_TO_NETWORK_PAYLOAD)
        payload['filter']['uuid'] = agent_uuid
        request_url = urlparse.urljoin(self.api_root, CONNECT_AGENT_TO_NETWORK_URL.format(agent_uuid))
        response = self.session.post(request_url, json=payload)
        self.validate_response(response)
        return True

    def create_path_exclusion(self, path, os_type):
        """
        Create an exclusion of pth type.
        :param path: {string} Target path.
        :param os_type: {string} can be windows, windows_legacy, macos or linux.
        :return: {bool} True if succeed.
        """
        payload = copy.deepcopy(CREATE_PATH_EXCLUSION_PAYLOAD)
        payload['data']['osType'] = os_type
        payload['data']['value'] = path
        request_url = urlparse.urljoin(self.api_root, CREATE_PATH_EXCLUSION_URL)
        response = self.session.post(request_url, json=payload)
        self.validate_response(response)
        return True

    def create_hash_exclusion(self, hash, os_type):
        payload = copy.deepcopy(CREATE_HASH_EXCLUSION_PAYLOAD)
        payload['data']['osType'] = os_type
        payload['data']['value'] = hash
        payload['data']['type'] = "black_hash"
        request_url = urlparse.urljoin(self.api_root, CREATE_HASH_EXCLUSION_URL)
        response = self.session.post(request_url, json=payload)
        self.validate_response(response)
        return True

    def initialize_get_events_for_agent_query(self, agent_uuid, from_date, to_date):
        """
        Initialize query for getting events for an agent in a specific time frame
        :param agent_uuid: {unicode} The UUID of the agent
        :param from_date: {long} Timestamp in milliseconds to get events from
        :param to_date: {long} Timestamp in milliseconds to get events up to
        :return: {unicode} The query ID
        """
        request_url = urlparse.urljoin(self.api_root, QUERY_URL)
        payload = {
            u"query": u"AgentUUID = \"{}\"".format(agent_uuid),
            u"fromDate": from_date,
            u"toDate": to_date,
            u"timeFrame": u"Custom",
            u"queryType": [
                u"events"
            ]
        }
        response = self.session.post(request_url, json=payload)
        self.validate_response(response)
        return response.json().get('data', {}).get('queryId')

    def initialize_query(self, query, from_date, to_date):
        """
        Initialize a query for a specific time frame
        :param query: {unicode} The query to run
        :param from_date: {long} Timestamp in milliseconds to get events from
        :param to_date: {long} Timestamp in milliseconds to get events up to
        :return: {unicode} The query ID
        """
        request_url = urlparse.urljoin(self.api_root, QUERY_URL)
        payload = {
            u"query": query,
            u"fromDate": from_date,
            u"toDate": to_date,
            u"timeFrame": u"Custom",
            u"queryType": [
                u"events"
            ]
        }
        response = self.session.post(request_url, json=payload)
        self.validate_response(response)
        return response.json().get(u'data', {}).get(u'queryId')

    def get_query_status(self, query_id):
        """
        Get the current status of a query by its ID
        :param query_id: {unicode} The ID of the query
        :return: {unicode} The status of the query
        """
        request_url = urlparse.urljoin(self.api_root, QUERY_STATUS_URL)
        response = self.session.get(request_url, params={u"queryId": query_id})
        self.validate_response(response)
        return response.json().get(u'data', {}).get(u'status')

    def is_query_has_results(self, query_id):
        """
        Check if a query has results or not
        :param query_id: {unicode} The ID of the query
        :return: {bool} True if there are results, False otherwise
        """
        request_url = urlparse.urljoin(self.api_root, QUERY_STATUS_URL)
        response = self.session.get(request_url, params={u"queryId": query_id})
        self.validate_response(response)
        return response.json().get(u'data', {}).get(u'hasData')

    def is_query_completed(self, query_id):
        """
        Check if a given query has completed
        :param query_id: {unicode} The ID of the query
        :return: {bool} True if completed, False otherwise
        """
        status = self.get_query_status(query_id)
        return status in COMPLETED_QUERY_STATUSES

    def is_query_failed(self, query_id):
        """
        Check if a given query has failed
        :param query_id: {unicode} The ID of the query
        :return: {bool} True if failed, False otherwise
        """
        status = self.get_query_status(query_id)
        return status in FAILED_QUERY_STATUSES

    def get_all_events_by_query_id(self, query_id, limit=None, existing_hashes=[]):
        """
        Get events of all types for a given query
        :param query_id: {unicode} The ID of the query
        :param limit: {int} The max amount of results to return
        :param existing_hashes: {[]} List of hashes of already seen events to filter those events out
        :return: {[Event]} The found events
        """
        request_url = urlparse.urljoin(self.api_root, GET_ALL_EVENTS_URL)
        params = {
            u"queryId": query_id,
            u"sortBy": u"createdAt",
            u"sortOrder": u"asc",
            u"limit": min(DEFAULT_PAGE_SIZE, limit)
        }

        response = self.session.get(request_url, params=params)
        self.validate_response(response, u"Unable to get events for query {}".format(query_id))

        results = response.json().get(u"data", [])
        events = [self.parser.build_siemplify_event_obj(event) for event in results]
        filtered_events = [event for event in events if event.to_hash() not in existing_hashes]

        while True:
            if limit and len(filtered_events) >= limit:
                # Got to limit of how many events to bring back - stop pagination
                break

            if len(events) >= MAXIMUM_EVENTS_ALLOWED:
                # Because we are looping in asc createdAt, we might reach a situation when all 1000
                # events are already seen and but we cannot loop more. If we did find some new events, we
                # should return them. But if there are NO new events, this means that we will soon reach a point
                # where all 1000 events are of the same timestamp, and the connector will get stuck.
                # So to avoid this, we should raise a proper exception here so the connector will know
                # increase the timestamp by at least 1 ms to avoid looping.
                if filtered_events:
                    break

                else:
                    raise SentinelOneV2ApiLimitError(u"Found {} or more events for query {}, but non of them are new. "
                                                     u"Due to API limitations, no more events can be retrieved, and "
                                                     u"therefore some events might be missed. "
                                                     u"Please tune your queries.".format(len(events), query_id)
                                                     )

            if len(events) >= response.json().get(u'pagination', {}).get(u'totalItems'):
                # No more pages to paginate
                break

            params.update({
                u"skip": len(events)
            })

            response = self.session.get(request_url, params=params)
            self.validate_response(response, u"Unable to get events for query {}".format(query_id))

            results = response.json().get(u"data", [])
            parsed_events = [self.parser.build_siemplify_event_obj(event) for event in results]
            events.extend(parsed_events)
            filtered_events.extend([event for event in parsed_events if event.to_hash() not in existing_hashes])

        return filtered_events[:limit] if limit else filtered_events

    def get_process_events_by_query_id(self, query_id, limit=None):
        """
        Get events of type process for a given query
        :param query_id: {unicode} The ID of the query
        :param limit: {int} The max amount of results to return
        :return: {[ProcessEvent]} The found events
        """
        request_url = urlparse.urljoin(self.api_root, GET_PROCESS_EVENTS_URL)
        events = self._paginate_results(
            method=u"GET",
            url=request_url,
            params={u"queryId": query_id},
            limit=limit,
            err_msg=u"Unable to get process events for query {}".format(query_id)
        )
        return [self.parser.build_siemplify_process_event_obj(event) for event in events]

    def get_file_events_by_query_id(self, query_id, limit=None):
        """
        Get events of type file for a given query
        :param query_id: {unicode} The ID of the query
        :param limit: {int} The max amount of results to return
        :return: {[FileEvent]} The found events
        """
        request_url = urlparse.urljoin(self.api_root, GET_FILE_EVENTS_URL)
        events = self._paginate_results(
            method=u"GET",
            url=request_url,
            params={u"queryId": query_id},
            limit=limit,
            err_msg=u"Unable to get process events for query {}".format(query_id)
        )
        return [self.parser.build_siemplify_file_event_obj(event) for event in events]

    def get_indicator_events_by_query_id(self, query_id, limit=None):
        """
        Get events of type indicator for a given query
        :param query_id: {unicode} The ID of the query
        :param limit: {int} The max amount of results to return
        :return: {[IndicatorEvent]} The found events
        """
        request_url = urlparse.urljoin(self.api_root, GET_INDICATOR_EVENTS_URL)
        events = self._paginate_results(
            method=u"GET",
            url=request_url,
            params={u"queryId": query_id},
            limit=limit,
            err_msg=u"Unable to get indicator events for query {}".format(query_id)
        )
        return [self.parser.build_siemplify_indicator_event_obj(event) for event in events]

    def get_dns_events_by_query_id(self, query_id, limit=None):
        """
        Get events of type dns for a given query
        :param query_id: {unicode} The ID of the query
        :param limit: {int} The max amount of results to return
        :return: {[DNSEvent]} The found events
        """
        request_url = urlparse.urljoin(self.api_root, GET_DNS_EVENTS_URL)
        events = self._paginate_results(
            method=u"GET",
            url=request_url,
            params={u"queryId": query_id},
            limit=limit,
            err_msg=u"Unable to get dns events for query {}".format(query_id)
        )
        return [self.parser.build_siemplify_dns_event_obj(event) for event in events]

    def get_network_actions_events_by_query_id(self, query_id, limit=None):
        """
        Get events of type Network Actions for a given query
        :param query_id: {unicode} The ID of the query
        :param limit: {int} The max amount of results to return
        :return: {[NetworkActionsEvent]} The found events
        """
        request_url = urlparse.urljoin(self.api_root, GET_NETWORK_ACTIONS_EVENTS_URL)
        events = self._paginate_results(
            method=u"GET",
            url=request_url,
            params={u"queryId": query_id},
            limit=limit,
            err_msg=u"Unable to get network actions events for query {}".format(query_id)
        )
        return [self.parser.build_siemplify_network_actions_event_obj(event) for event in events]

    def get_url_events_by_query_id(self, query_id, limit=None):
        """
        Get events of type URL for a given query
        :param query_id: {unicode} The ID of the query
        :param limit: {int} The max amount of results to return
        :return: {[URLEvent]} The found events
        """
        request_url = urlparse.urljoin(self.api_root, GET_URL_EVENTS_URL)
        events = self._paginate_results(
            method=u"GET",
            url=request_url,
            params={u"queryId": query_id},
            limit=limit,
            err_msg=u"Unable to get url events for query {}".format(query_id)
        )
        return [self.parser.build_siemplify_url_event_obj(event) for event in events]

    def get_registry_events_by_query_id(self, query_id, limit=None):
        """
        Get events of type registry for a given query
        :param query_id: {unicode} The ID of the query
        :param limit: {int} The max amount of results to return
        :return: {[RegistryEvent]} The found events
        """
        request_url = urlparse.urljoin(self.api_root, GET_REGISTRY_EVENTS_URL)
        events = self._paginate_results(
            method=u"GET",
            url=request_url,
            params={u"queryId": query_id},
            limit=limit,
            err_msg=u"Unable to get registry events for query {}".format(query_id)
        )
        return [self.parser.build_siemplify_registry_event_obj(event) for event in events]

    def get_scheduled_task_events_by_query_id(self, query_id, limit=None):
        """
        Get events of type scheduled task for a given query
        :param query_id: {unicode} The ID of the query
        :param limit: {int} The max amount of results to return
        :return: {[ScheduledTaskEvent]} The found events
        """
        request_url = urlparse.urljoin(self.api_root, GET_SCHEDULED_TASK_EVENTS_URL)
        events = self._paginate_results(
            method=u"GET",
            url=request_url,
            params={u"queryId": query_id},
            limit=limit,
            err_msg=u"Unable to get scheduled task events for query {}".format(query_id)
        )
        return [self.parser.build_siemplify_scheduled_task_event_obj(event) for event in events]

    def get_threat_forensic_information(self, threat_id):
        request_url = urlparse.urljoin(self.api_root, GET_THREAT_FORENSIC_DETAILS_URL.format(threat_id))
        response = self.session.get(request_url)
        self.validate_response(response)
        return response.json().get('data', []).get('result', [])

    def get_unresolved_threats_by_time(self, from_time=datetime.datetime.now()):
        """
        Get unresolved threats for time greated then set.
        :param from_time: {datetime} Time to fetch from.
        :return: {list} List of dicts when each represents a threats.
        """
        request_url = urlparse.urljoin(self.api_root, GET_THREATS_URL)
        params = copy.deepcopy(GET_THREATS_PARAMS)
        params['createdAt__gt'] = from_time.strftime(FETCH_EVENT_TIME_FORMAT)
        response = self.session.get(request_url, params=params)
        self.validate_response(response)
        return response.json().get('data', [])

    def mitigate_threat(self, threat_id, threat_action):
        available_commands = self.get_available_threat_actions(threat_id)
        for command in available_commands:
            if command.get('name') == threat_action and not command.get('isDisabled'):
                request_url = urlparse.urljoin(self.api_root, MITIGATE_THREAT_URL.format(threat_action))
                payload = copy.deepcopy(MITIGATE_THREAT_PARAMS)
                payload['filter']['ids'] = threat_id
                response = self.session.post(request_url, json=payload)
                self.validate_response(response)
                return response.json().get('data', [])
            else:
                return "Not supported on the agent's platform / version"

    def get_available_threat_actions(self, threat_id):
        request_url = urlparse.urljoin(self.api_root, GET_THREAT_ACTIONS_URL)
        payload = copy.deepcopy(MARK_THREAT_RESOLVED_PARAMS)
        payload['filter']['ids'] = threat_id
        response = self.session.get(request_url, json=payload)
        self.validate_response(response)
        return response.json().get('data', [])

    def annotate_threat(self, threat_id, annotation_string=None):
        request_url = urlparse.urljoin(self.api_root, MARK_THREAT_URL.format(threat_id))
        params = copy.deepcopy(ANNOTATE_THREAT_PARAMS)
        params['data']['annotation'] = annotation_string
        response = self.session.put(request_url, json=params)
        self.validate_response(response)
        return response.json().get('data', [])

    def mark_threats_as_resolved(self, threat_id, annotation_string=None):
        request_url = urlparse.urljoin(self.api_root, RESOLVE_THREAT_URL)

        if annotation_string:
            params = copy.deepcopy(MARK_THREAT_RESOLVED_ANNOTATE_PARAMS)
            params['data']['annotation'] = annotation_string
        else:
            params = copy.deepcopy(MARK_THREAT_RESOLVED_PARAMS)

        params['filter']['ids'] = threat_id

        response = self.session.post(request_url, json=params)
        self.validate_response(response)
        return response.json().get('data', [])

    def mark_threats_as_threat(self, threat_id, annotation_string=None):
        request_url = urlparse.urljoin(self.api_root, MARK_THREAT_URL.format("mark-as-threat"))

        if annotation_string:
            params = copy.deepcopy(MARK_THREAT_RESOLVED_ANNOTATE_PARAMS)
            params['data']['annotation'] = annotation_string
        else:
            params = copy.deepcopy(MARK_THREAT_RESOLVED_PARAMS)

        params['filter']['ids'] = threat_id

        response = self.session.post(request_url, json=params)
        self.validate_response(response)
        return response.json().get('data', [])

    def mark_threats_as_benign(self, threat_id, annotation_string=None):
        request_url = urlparse.urljoin(self.api_root, MARK_THREAT_URL.format("mark-as-benign"))

        if annotation_string:
            params = copy.deepcopy(MARK_THREAT_RESOLVED_ANNOTATE_PARAMS)
            params['data']['annotation'] = annotation_string
        else:
            params = copy.deepcopy(MARK_THREAT_RESOLVED_PARAMS)

        params['filter']['ids'] = threat_id

        response = self.session.post(request_url, json=params)
        self.validate_response(response)
        return response.json().get('data', [])

    def _paginate_results(self, method, url, params=None, body=None, limit=None, err_msg=u"Unable to get results"):
        """
        Paginate the results of a job
        :param method: {str} The method of the request (GET, POST, PUT, DELETE, PATCH)
        :param url: {str} The url to send request to
        :param params: {dict} The params of the request
        :param body: {dict} The json payload of the request
        :param limit: {int} The limit of the results to fetch
        :param err_msg: {str} The message to display on error
        :return: {list} List of results
        """
        if params is None:
            params = {}

        params.update({
            u"limit": DEFAULT_PAGE_SIZE
        })

        response = self.session.request(method, url, params=params, json=body)

        self.validate_response(response, err_msg)
        results = response.json().get("data", [])

        while True:
            if limit and len(results) >= limit:
                break

            if not response.json().get("pagination", {}).get("nextCursor"):
                break

            params.update({
                "cursor": response.json().get("pagination", {}).get("nextCursor")
            })

            response = self.session.request(method, url, params=params, json=body)

            self.validate_response(response, err_msg)
            results.extend(response.json().get("data", []))

        return results[:limit] if limit else results

