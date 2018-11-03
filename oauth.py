import json

from rauth import OAuth2Service
from flask import current_app, url_for, request, redirect


class OAuthSignIn(object):
    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'][provider_name]
        self.consumer_id = credentials['id']
        self.consumer_secret = credentials['secret']

    def authorize(self):
        pass

    def callback(self):
        pass

    def get_callback_url(self):
        return url_for('oauth_callback', provider=self.provider_name,
                       _external=True)

    @classmethod
    def get_provider(self, provider_name):
        if self.providers is None:
            self.providers = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.providers[provider.provider_name] = provider
        return self.providers[provider_name]


class DropBoxSignIn(OAuthSignIn):
    def __init__(self):
        super(DropBoxSignIn, self).__init__('dropbox')
        self.service = OAuth2Service(
            name='dropbox',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://www.dropbox.com/oauth2/authorize',
            access_token_url='https://www.dropbox.com/oauth2/token',
            base_url='https://api.dropboxapi.com'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):

        def decode_json(payload):
            return json.loads(payload.decode('utf-8'))

        if 'code' not in request.args:
            return None, None, None

        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url(),
                  'client_secret': self.service.client_secret,
                  'client_id': self.service.client_id
                  },
            decoder=decode_json
        )

        session = self.service.get_session(token=oauth_session.access_token)

        req = session.request("POST", 'https://api.dropboxapi.com/2/users/get_current_account', True)
        data = req.json()
        social_id = 'dropbox$' + data['account_id'].split(':')[1]
        email = data['email']
        username = email.split('@')[0]
        return social_id,  username, data['email']




