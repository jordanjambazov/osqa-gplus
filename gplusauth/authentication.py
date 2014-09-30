# -*- coding: utf-8 -*-

import os.path
import urllib
import string
import random
import json

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from django.conf import settings as django_settings
from forum.authentication.base import AuthenticationConsumer, ConsumerTemplateContext, InvalidAuthentication

CLIENT_SECRETS_PATH = os.path.join(django_settings.SITE_SRC_ROOT, 'client_secrets.json')
CLIENT_ID = json.loads(open(CLIENT_SECRETS_PATH, 'r').read())['web']['client_id']


class GooglePlusAuthConsumer(AuthenticationConsumer):

    def prepare_authentication_request(self, request, redirect_to):
        state = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(32))
        request.session['gplus_state'] = state
        request_data = dict(
            redirect_uri="{0}{1}".format(django_settings.APP_URL, redirect_to),
            scope="https://www.googleapis.com/auth/plus.login https://www.googleapis.com/auth/plus.profile.emails.read",
            state=state,
            response_type="code",
            client_id=CLIENT_ID,
            access_type="offline"
        )
        login_url = 'https://accounts.google.com/o/oauth2/auth?' + urllib.urlencode(request_data)
        return login_url

    def process_authentication_request(self, request):
        request_state = request.GET['state']
        session_state = request.session['gplus_state']
        if request_state != session_state:
            raise InvalidAuthentication("Request State Did Not Match")
        code = request.GET['code']
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets(CLIENT_SECRETS_PATH, scope='')
            oauth_flow.redirect_uri = '{0}/account/googleplus/done/'.format(
                django_settings.APP_URL
            )
            credentials = oauth_flow.step2_exchange(code)
        except FlowExchangeError:
            raise InvalidAuthentication("Could not exchange flows")
        access_token = credentials.access_token
        assoc_key = credentials.id_token['sub']
        request.session["access_token"] = access_token
        request.session["assoc_key"] = assoc_key
        return assoc_key

    def get_user_data(self, assoc_key):
        return {}


class GooglePlusAuthContext(ConsumerTemplateContext):
    mode = 'BIGICON'
    type = 'CUSTOM'
    weight = 100
    human_name = 'Google+'
    code_template = 'modules/gplusauth/button.html'
    extra_css = []
