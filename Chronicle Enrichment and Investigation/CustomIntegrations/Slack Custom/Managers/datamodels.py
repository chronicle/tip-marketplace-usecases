# =====================================
#              IMPORTS                #
# =====================================
from abc import ABCMeta, abstractmethod

from SiemplifyUtils import dict_to_flat


# =====================================
#              CLASSES                #
# =====================================


class AbstractData(object):
    """
    Abstract Data Model for others Data Models
    """
    __metaclass__ = ABCMeta

    def to_table(self):
        return [self.to_json()]

    def to_csv(self):
        return dict_to_flat(self.to_json())

    @abstractmethod
    def to_json(self):
        pass

    @abstractmethod
    def to_enrichment_data(self):
        pass


class Profile(AbstractData):
    """
    Profile Data Model
    """

    def __init__(self, team=None, real_name=None, skype=None, email=None, **kwargs):
        self.team = team
        self.real_name = real_name
        self.skype = skype
        self.email = email

    def to_json(self):
        return {
            'Team': self.team,
            'Real Name': self.real_name,
            'Skype': self.skype,
            'Email': self.email,
        }

    def to_enrichment_data(self):
        pass


class User(AbstractData):
    """
    User Data Model
    """

    def __init__(self, raw_data, name=None, real_name=None, id=None, deleted=None, is_app_user=None, is_bot=None,
                 team_id=None, is_admin=None, is_restricted=None, is_ultra_restricted=None, is_owner=None,
                 is_primary_owner=None, profile=None, **kwargs):
        self.raw_data = raw_data
        self.name = name
        self.real_name = real_name
        self.id = id
        self.deleted = deleted
        self.is_app_user = is_app_user
        self.is_bot = is_bot
        self.team_id = team_id
        self.is_admin = is_admin
        self.is_restricted = is_restricted
        self.is_ultra_restricted = is_ultra_restricted
        self.is_owner = is_owner
        self.is_primary_owner = is_primary_owner
        self.profile = Profile(**profile)

    def to_json(self):
        return {
            'Name': self.name,
            'Real Name': self.real_name,
            'ID': self.id,
            'Is Deleted': self.deleted,
            'Is App User': self.is_app_user,
            'Is Bot': self.is_bot,
            'Team ID': self.team_id,
            'Is Admin': self.is_admin,
            'Is Restricted': self.is_restricted,
            'Is Ultra Restricted': self.is_ultra_restricted,
            'Is Owner': self.is_owner,
            'Is Primary Owner': self.is_primary_owner,
            'Profile': self.profile.to_json() if self.profile else None,
        }

    def to_enrichment_data(self):
        pass


class Channel(AbstractData):
    """
    Channel Data Model
    """

    def __init__(self, raw_data, name=None, name_normalized=None, creator=None, is_org_shared=None, is_channel=None,
                 is_general=None, id=None, is_private=None, is_shared=None, **kwargs):
        self.raw_data = raw_data
        self.name = name
        self.name_normalized = name_normalized
        self.creator = creator
        self.is_org_shared = is_org_shared
        self.is_channel = is_channel
        self.is_general = is_general
        self.id = id
        self.is_private = is_private
        self.is_shared = is_shared

    def to_json(self):
        return {
            'Name': self.name,
            'Normalized Name': self.name_normalized,
            'Creator': self.creator,
            'Is Org Shared': self.is_org_shared,
            'Is Channel': self.is_channel,
            'Is General': self.is_general,
            'ID': self.id,
            'Is Private': self.is_private,
            'Is Shared': self.is_shared,
        }

    def to_enrichment_data(self):
        pass


class Message(AbstractData):
    """
    Message Data Model
    """

    def __init__(self, raw_data, ts=None, text=None, user=None, type=None, **kwargs):
        self.raw_data = raw_data
        self.ts = ts
        self.text = text
        self.user = user
        self.type = type

    def to_enrichment_data(self):
        pass

    def to_json(self):
        return {
            'Timestamp': self.ts,
            'Text': self.text,
            'User': self.user,
            'Type': self.type
        }