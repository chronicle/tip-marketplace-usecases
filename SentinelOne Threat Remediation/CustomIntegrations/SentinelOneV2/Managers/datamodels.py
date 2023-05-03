from SiemplifyUtils import convert_string_to_unix_time, dict_to_flat
import json
import copy
import hashlib


COMPLETED_QUERY_STATUSES = [u'FAILED', u'FINISHED', u'ERROR', u'QUERY_CANCELLED', u'TIMED_OUT']
FAILED_QUERY_STATUSES = [u'FAILED', u'ERROR', u'QUERY_CANCELLED', u'TIMED_OUT']


class SystemStatus(object):
    def __init__(self, raw_data, is_ok=False, errors=[]):
        self.raw_data = raw_data
        self.is_ok = is_ok
        self.errors = errors


class AgentInterface(object):
    def __init__(self, raw_data, inet6=None, id=None, name=None, inet=None, physical=None):
        self.raw_data = raw_data
        self.inet6 = inet6
        self.id = id
        self.name = name
        self.inet = inet
        self.physical = physical


class Agent(object):
    def __init__(self, raw_data, uuid=None, accountName=None, osUsername=None, siteId=None, isDecommissioned=None,
                 accountId=None, machineType=None, isUpToDate=None, createdAt=None, isActive=None, domain=None,
                 osName=None, modelName=None, osType=None, groupIp=None, id=None, agentVersion=None, groupId=None,
                 groupName=None, siteName=None, externalId=None, lastActiveDate=None, computerName=None,
                 networkStatus=None, totalMemory=None, osStartTime=None, scanStatus=None, updatedAt=None,
                 externalIp=None, interfaces=[], **kwargs):
        self.raw_data = raw_data
        self.uuid = uuid
        self.account_name = accountName
        self.os_username = osUsername
        self.site_id = siteId
        self.is_decommissioned = isDecommissioned
        self.account_id = accountId
        self.machine_type = machineType
        self.is_up_to_date = isUpToDate
        self.created_at = createdAt
        self.is_active = isActive
        self.domain = domain
        self.os_name = osName
        self.model_name = modelName
        self.os_type = osType
        self.group_ip = groupIp
        self.id = id
        self.agent_version = agentVersion
        self.group_id = groupId
        self.group_name = groupName
        self.site_name = siteName
        self.external_id = externalId
        self.last_active_date = lastActiveDate
        self.computer_name = computerName
        self.network_status = networkStatus
        self.total_memory = totalMemory
        self.os_start_time = osStartTime
        self.scan_status = scanStatus
        self.updated_at = updatedAt
        self.external_ip = externalIp
        self.interfaces = interfaces

    def to_json(self):
        return self.raw_data


class Group(object):
    def __init__(self, raw_data, id=None, name=None, inherits=None, creator=None, filterName=None, updatedAt=None,
                 filterId=None, rank=None, registrationToken=None, siteId=None, isDefault=None, creatorId=None,
                 totalAgents=None, type=None, createdAt=None):
        self.raw_data = raw_data
        self.id = id
        self.group_name = name
        self.inherits = inherits
        self.creator = creator
        self.filter_name = filterName
        self.updated_at = updatedAt
        self.filter_id = filterId
        self.rank = rank
        self.registration_token = registrationToken
        self.site_id = siteId
        self.is_default = isDefault
        self.creator_id = creatorId
        self.total_agents = totalAgents
        self.type = type
        self.created_at = createdAt

    def to_csv(self):
        return {
            u"Group Name": self.group_name,
            u"Group Type": self.type,
            u"Total Agents Assigned": self.total_agents,
            u"Default Group": self.is_default,
            u"Date Created": self.created_at,
            u"Date Updated": self.updated_at,
            u"Inherits": self.inherits,
        }

    def to_json(self):
        return self.raw_data


class Event(object):
    def __init__(self, raw_data, agentId=None, agentIp=None, agentName=None, agentOs=None, agentUuid=None,
                 agentVersion=None, createdAt=None, eventType=None, id=None, pid=None, user=None, processName=None,
                 relatedToThreat=None, objectType=None, uuid=None, trueContext=None, **kwargs):
        self.raw_data = raw_data
        self.agent_id = agentId
        self.agent_ip = agentIp
        self.agent_name = agentName
        self.agent_os = agentOs
        self.agent_uuid = agentUuid
        self.agent_version = agentVersion
        self.created_at = createdAt
        self.event_type = eventType
        self.id = id
        self.raw_data = raw_data
        self.pid = pid
        self.process_name = processName
        self.related_to_threat = relatedToThreat
        self.user = user
        self.object_type = objectType
        self.uuid = uuid
        self.true_context = trueContext

        try:
            # Try parsing the created_at timestamp to unix time
            self.creation_time_unix_time = convert_string_to_unix_time(self.created_at)
        except Exception:
            self.creation_time_unix_time = 1

    def to_csv(self):
        return {
            u"Agent Name": self.agent_name,
            u"Agent OS": self.agent_os,
            u"Agent IP": self.agent_ip,
            u"Event Type": self.event_type,
            u"Related To Threat": self.related_to_threat,
            u"PID": self.pid,
            u"Process Name": self.process_name,
            u"Username": self.user,
            u"Creation Time": self.created_at
        }

    def to_json(self):
        temp = copy.deepcopy(self.raw_data)
        temp.update({
            u"creation_time_unix_time": self.creation_time_unix_time
        })
        return temp

    def to_event(self):
        return dict_to_flat(self.to_json())

    def to_hash(self):
        temp = copy.deepcopy(self.raw_data)
        if u'id' in temp:
            del temp[u'id']

        return hashlib.md5(json.dumps(dict_to_flat(temp), sort_keys=True)).hexdigest()


class ProcessEvent(Event):
    def __init__(self, raw_data, agentId=None, agentIp=None, agentName=None, agentOs=None, agentUuid=None,
                 agentVersion=None, createdAt=None, eventType=None, id=None, hasParent=None, md5=None, parentPid=None,
                 parentProcessName=None, pid=None, processDisplayName=None, processCmd=None, processName=None,
                 relatedToThreat=None, signedStatus=None, user=None, objectType=None, uuid=None, trueContext=None,
                 **kwargs):
        super(ProcessEvent, self).__init__(raw_data, agentId, agentIp, agentName, agentOs, agentUuid,
                                           agentVersion, createdAt, eventType, id, pid, user, processName,
                                           relatedToThreat, objectType, uuid, trueContext)
        self.has_parent = hasParent
        self.md5 = md5
        self.parent_pid = parentPid
        self.parent_process_name = parentProcessName
        self.process_display_name = processDisplayName
        self.process_cmd = processCmd
        self.signed_status = signedStatus

    def to_csv(self):
        csv = super(ProcessEvent, self).to_csv()
        csv.update(
            {
                u"Command Line": self.process_cmd,
                u"Signed Status": self.signed_status,
                u"Parent PID": self.parent_pid,
                u"Parent Process Name": self.parent_process_name
            }
        )
        return csv


class FileEvent(Event):
    def __init__(self, raw_data, agentId=None, agentIp=None, agentName=None, agentOs=None, agentUuid=None,
                 agentVersion=None, createdAt=None, eventType=None, id=None, hasParent=None,
                 fileFullName=None, pid=None, processName=None, relatedToThreat=None, user=None,
                 objectType=None, uuid=None, trueContext=None, **kwargs):
        super(FileEvent, self).__init__(raw_data, agentId, agentIp, agentName, agentOs, agentUuid,
                                        agentVersion, createdAt, eventType, id, pid, user, processName,
                                        relatedToThreat, objectType, uuid, trueContext)
        self.has_parent = hasParent
        self.file_full_name = fileFullName

    def to_csv(self):
        csv = super(FileEvent, self).to_csv()
        csv.update(
            {
                u"File name": self.file_full_name
            }
        )
        return csv


class IndicatorEvent(Event):
    def __init__(self, raw_data, agentId=None, agentIp=None, agentName=None, agentOs=None, agentUuid=None,
                 agentVersion=None, createdAt=None, eventType=None, id=None, indicatorName=None,
                 indicatorCategory=None, indicatorMetadata=None, pid=None, processName=None, relatedToThreat=None,
                 user=None, objectType=None, uuid=None, trueContext=None, **kwargs):
        super(IndicatorEvent, self).__init__(raw_data, agentId, agentIp, agentName, agentOs, agentUuid,
                                             agentVersion, createdAt, eventType, id, pid, user, processName,
                                             relatedToThreat, objectType, uuid, trueContext)
        self.indicator_name = indicatorName
        self.indicator_category = indicatorCategory
        self.indicator_metadata = indicatorMetadata

    def to_csv(self):
        csv = super(IndicatorEvent, self).to_csv()
        csv.update(
            {
                u"Indicator Name": self.indicator_name,
                u"Indicator Category": self.indicator_category,
                u"Indicator Metadata": self.indicator_metadata
            }
        )
        return csv


class DNSEvent(Event):
    def __init__(self, raw_data, agentId=None, agentIp=None, agentName=None, agentOs=None, agentUuid=None,
                 agentVersion=None, createdAt=None, eventType=None, id=None, dnsRequest=None,
                 dnsResponse=None, pid=None, processName=None, relatedToThreat=None,
                 user=None, objectType=None, uuid=None, trueContext=None, **kwargs):
        super(DNSEvent, self).__init__(raw_data, agentId, agentIp, agentName, agentOs, agentUuid,
                                       agentVersion, createdAt, eventType, id, pid, user, processName,
                                       relatedToThreat, objectType, uuid, trueContext)
        self.dns_request = dnsRequest
        self.dns_response = dnsResponse

    def to_csv(self):
        csv = super(DNSEvent, self).to_csv()
        csv.update(
            {
                u"DNS Request": self.dns_request,
                u"DNS Response": self.dns_response
            }
        )
        return csv


class NetworkActionsEvent(Event):
    def __init__(self, raw_data, agentId=None, agentIp=None, agentName=None, agentOs=None, agentUuid=None,
                 agentVersion=None, createdAt=None, eventType=None, id=None, dstIp=None, dstPort=None,
                 direction=None, connectionStatus=None, pid=None, processName=None, relatedToThreat=None,
                 user=None, objectType=None, uuid=None, trueContext=None, **kwargs):
        super(NetworkActionsEvent, self).__init__(raw_data, agentId, agentIp, agentName, agentOs, agentUuid,
                                                  agentVersion, createdAt, eventType, id, pid, user, processName,
                                                  relatedToThreat, objectType, uuid, trueContext)
        self.dst_ip = dstIp
        self.dst_port = dstPort
        self.direction = direction
        self.connection_status = connectionStatus

    def to_csv(self):
        csv = super(NetworkActionsEvent, self).to_csv()
        csv.update(
            {
                u"Destination IP": self.dst_ip,
                u"Destination Port": self.dst_port,
                u"Direction": self.direction,
                u"Connection Status": self.connection_status
            }
        )
        return csv


class URLEvent(Event):
    def __init__(self, raw_data, agentId=None, agentIp=None, agentName=None, agentOs=None, agentUuid=None,
                 agentVersion=None, createdAt=None, eventType=None, id=None, networkUrl=None, networkSource=None,
                 pid=None, processName=None, relatedToThreat=None,
                 user=None, objectType=None, uuid=None, trueContext=None, **kwargs):
        super(URLEvent, self).__init__(raw_data, agentId, agentIp, agentName, agentOs, agentUuid,
                                       agentVersion, createdAt, eventType, id, pid, user, processName,
                                       relatedToThreat, objectType, uuid, trueContext)
        self.url = networkUrl
        self.source = networkSource

    def to_csv(self):
        csv = super(URLEvent, self).to_csv()
        csv.update(
            {
                u"URL": self.url,
                u"Source": self.source,

            }
        )
        return csv


class RegistryEvent(Event):
    def __init__(self, raw_data, agentId=None, agentIp=None, agentName=None, agentOs=None, agentUuid=None,
                 agentVersion=None, createdAt=None, eventType=None, id=None, registryId=None,
                 registryPath=None, pid=None, processName=None, relatedToThreat=None,
                 user=None, objectType=None, uuid=None, trueContext=None, **kwargs):
        super(RegistryEvent, self).__init__(raw_data, agentId, agentIp, agentName, agentOs, agentUuid,
                                            agentVersion, createdAt, eventType, id, pid, user, processName,
                                            relatedToThreat, objectType, uuid, trueContext)
        self.registry_id = registryId
        self.registry_path = registryPath

    def to_csv(self):
        csv = super(RegistryEvent, self).to_csv()
        csv.update(
            {
                u"Registry ID": self.registry_id,
                u"Registry Path": self.registry_path
            }
        )
        return csv


class ScheduledTaskEvent(Event):
    def __init__(self, raw_data, agentId=None, agentIp=None, agentName=None, agentOs=None, agentUuid=None,
                 agentVersion=None, createdAt=None, eventType=None, id=None, taskName=None,
                 taskPath=None, pid=None, processName=None, relatedToThreat=None,
                 user=None, objectType=None, uuid=None, trueContext=None, **kwargs):
        super(ScheduledTaskEvent, self).__init__(raw_data, agentId, agentIp, agentName, agentOs, agentUuid,
                                                 agentVersion, createdAt, eventType, id, pid, user, processName,
                                                 relatedToThreat, objectType, uuid, trueContext)
        self.task_name = taskName
        self.task_path = taskPath

    def to_csv(self):
        csv = super(ScheduledTaskEvent, self).to_csv()
        csv.update(
            {
                u"Task Name": self.task_name,
                u"Task Path": self.task_path
            }
        )
        return csv
