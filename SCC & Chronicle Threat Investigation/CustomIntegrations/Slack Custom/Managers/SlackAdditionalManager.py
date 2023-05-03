# =====================================
#              IMPORTS                #
# =====================================
import os
import json
from slackclient import SlackClient
from SlackTransformationLayer import SlackTransformationLayer


# =====================================

#               CONSTS                #
# =====================================

METHODS = {
    'upload_file': 'files.upload',
    'send_message': 'chat.postMessage',
    'send_block_message': 'chat.postMessage',
    'get_user_details_by_id': 'users.info',
    'get_user_details_by_email': 'users.lookupByEmail',
    'list_users': 'users.list',
    'list_channels': 'conversations.list',
    'ask_question': 'chat.postMessage',
    'get_message_replies': 'conversations.replies',
    'test_connectivity': 'api.test',
    'create_channel': 'conversations.create',
    'invite_to_channel': 'conversations.invite',
    'rename_channel': 'conversations.rename'
}

MESSAGE_ATTACHMENTS = [
    {
        'fallback': 'Upgrade your Slack client to use messages like these.',
        'color': '#3AA3E3',
        'attachment_type': 'default',
        'callback_id': 'button_ask1',
        'actions': [
            {
                'name': 'yes',
                'text': 'Yes',
                'type': 'button'
            },
            {
                'name': 'no',
                'text': 'No',
                'type': 'button'
            }
        ],
    }
]

PAGE_SIZE = 100


# =====================================
#               CLASSES               #
# =====================================

class SlackManagerException(Exception):
    """ General Exception for Slack manager """
    pass


class UserNotFoundException(Exception):
    """ Exception when a user was not found """
    pass


class SlackAdditionalManager:
    def __init__(self, token, verify_ssl=False):
        self.client = SlackClient(token)
        self.tl = SlackTransformationLayer()

    def upload_file(self, file_name, file_path, channel):
        """
        Upload file to Slack channel.
        :param file_name: {string} Displayed file name.
        :param file_path: {string} Path to file.
        :param channel: {string} Name of the channel in Slack.
        :return: {string} Private file url.
        """
        if not os.access(file_path, os.R_OK):
            raise SlackManagerException(u'Permissions denied for path: {}'.format(file_path))

        if not os.path.exists(file_path):
            raise SlackManagerException(u'Path {} does not exist'.format(file_path))

        file_data = open(file_path, 'rb').read()

        response = self.client.api_call(
            METHODS['upload_file'],
            file=file_data,
            title=file_name,
            channels=channel
        )

        self._validate_response(response)

        return response.get('file', {}).get('url_private_download')

    def send_message(self, channel, message):
        """
        Send message to Slack channel
        :param channel: {string} Name of the channel or User ID in Slack.
        :param message: {string} Text to send.
        """
        response = self.client.api_call(
            METHODS['send_message'],
            channel=channel,
            text=message,
            
        )

        self._validate_response(response)
        return response
    
    def send_block_message(self, channel, message):
        """
        Send message to Slack channel
        :param channel: {string} Name of the channel or User ID in Slack.
        :param message: {string} Text to send.
        """
        response = self.client.api_call(
            METHODS['send_message'],
            channel=channel,
            blocks=message
        )

        self._validate_response(response)
        return response

    def get_user_details_by_id(self, user_id):
        """
        Get specific user by ID
        :param user_id: {string} ID of the user
        :return: {dict} User details.
        """
        response = self.client.api_call(
            METHODS['get_user_details_by_id'],
            user=user_id
        )

        self._validate_response(response)

        return self.tl.build_siemplify_user_obj(response['user'])

    def get_user_details_by_email(self, email):
        """
        Get specific user by email
        :param email: {string} Email of the user
        :return: {User} User details.
        """
        response = self.client.api_call(
            METHODS['get_user_details_by_email'],
            email=email
        )

        self._validate_response_customized(response)

        return self.tl.build_siemplify_user_obj(response['user'])

    def list_users(self):
        """
        Get all Users
        :return: {list[dict]} All users details.
        """
        response = self.client.api_call(
            METHODS['list_users']
        )

        self._validate_response(response)

        users = [self.tl.build_siemplify_user_obj(user_data) for user_data in response['members']]

        while response.get("response_metadata", {}).get("next_cursor"):
            response = self.client.api_call(
                METHODS['list_users'],
                cursor=response.get("response_metadata", {}).get("next_cursor")
            )

            self._validate_response(response)

            users.extend([self.tl.build_siemplify_user_obj(user_data) for user_data in response['members']])

        return users

    def list_channels(self, max_channels_to_return=None, types=None):
        """
        Get all Channels
        :param max_channels_to_return {int} Limit of number of channels
        :return: {list[dict]} All users details.
        """
        if types:
            response = self.client.api_call(
                METHODS['list_channels'],
                limit=min(max_channels_to_return, 100) if max_channels_to_return else 100,
                types=types
            )
        else:
            response = self.client.api_call(
                METHODS['list_channels'],
                limit=min(max_channels_to_return, 100) if max_channels_to_return else 100,
                types='public_channel,private_channel,mpim,im'
            )

        self._validate_response(response)

        channels = [self.tl.build_siemplify_channel_obj(channel_data) for channel_data in response['channels']]

        while response.get("response_metadata", {}).get("next_cursor"):
            if types:
                response = self.client.api_call(
                    METHODS['list_channels'],
                    limit=100,
                    types=types,
                    cursor=response.get("response_metadata", {}).get("next_cursor")
                )

            else:
                response = self.client.api_call(
                    METHODS['list_channels'],
                    limit=100,
                    cursor=response.get("response_metadata", {}).get("next_cursor"),
                    types='public_channel,private_channel,mpim,im'
                )

            self._validate_response(response)

            channels.extend(
                [self.tl.build_siemplify_channel_obj(channel_data) for channel_data in response['channels']])

        return channels[:max_channels_to_return] if max_channels_to_return else channels

    def get_channel_by_name(self, channel_name):
        """
        Get a channel by its name
        :param channel_name: {str} The name of the channel
        :return: {Channel} The found channel, or exception if a matching channel was not found
        """
        
        try:
            channels = self.list_channels(types="public_channel, private_channel")
            for channel in channels:
                if channel.name.lower() == channel_name.lower():
                    return channel
        
        except Exception as e:
            raise SlackManagerException(u"Channel {} was not found. "
                                    u"Please ensure the channel exists and "
                                    u"that the token has permissions to access it,".format(channel_name))

    def get_message_replies(self, conversation_id, message_ts):
        """
        Get the replies of a specific message (the messages in its thread)
        :param conversation_id: {str} The ID of the conversation to which the message belongs
        :param message_ts: {float} The timestamp of the message (milliseconds)
        :return: {[Message]} The replies of the message
        """
        response = self.client.api_call(
            METHODS['get_message_replies'],
            channel=conversation_id,
            ts=message_ts
        )

        self._validate_response(response)
        messages = response["messages"]

        if not messages:
            raise SlackManagerException(
                u"No messages were found with timestamp {} in the given conversation".format(message_ts))

        # Build the reply messages objects
        return [self.tl.build_siemplify_message_obj(message) for message in messages[1:]]

    def ask_question(self, channel, message):
        """
        Send message to Slack channel
        :param channel: {string} Name of the channel or User ID in Slack.
        :param message: {string} Text to send.
        """
        response = self.client.api_call(
            METHODS['ask_question'],
            channel=channel,
            text=message,
            attachments=MESSAGE_ATTACHMENTS
        )

        self._validate_response(response)

    def test_connectivity(self):
        """
        Test connection
        """

        response = self.client.api_call(
            METHODS['test_connectivity']
        )

        self._validate_response(response)

    @staticmethod
    def _validate_response(response):
        if not response.get('ok'):
            raise SlackManagerException(response['error'].replace('_', ' ').capitalize())

    @staticmethod
    def _validate_response_customized(response):
        if not response.get('ok'):
            if response.get('error') in [u"user_not_found", u"users_not_found"]:
                raise UserNotFoundException(response['error'].replace('_', ' ').capitalize())

            raise SlackManagerException(response['error'].replace('_', ' ').capitalize())

    def create_channel(self, channel_name, is_private=False):
        """
        Create Channel on Slack
        :param channel_name: {string} Name of the channel
        :param is_private: {bool} True if the new channel should be private
        :param channel: {Channel} Channel Object
        """
        response = self.client.api_call(
            METHODS['create_channel'],
            name=channel_name,
            is_private=is_private
        )

        self._validate_response(response)
        return self.tl.build_siemplify_channel_obj(response['channel'])

    def invite_to_channel(self, channel_id, user_ids):
        """
        Invite Users to a Slack channel
        :param channel_id: {string} ID of the channel
        :param user_ids: {string} Comma separated list of User IDs.
        """
        response = self.client.api_call("conversations.invite",
                                        channel=channel_id,
                                        users=user_ids
                                        )

        self._validate_response_customized(response)


    def rename_channel_by_id(self, channel_id, new_name):
        """
        Rename Channel 
        :param channel_id: {string} ID of the channel that will be renamed
        :param new_name: {string} New name of the channel
        """
        
        response = self.client.api_call(
            METHODS['rename_channel'],
            channel=channel_id,
            name=new_name
        )

        self._validate_response(response)
        return self.tl.build_siemplify_channel_obj(response['channel'])
        