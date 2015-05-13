# -*- coding: utf-8 -*-

import os.path
import urllib
import string
import random
import json

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from django.conf import settings as django_settings
from forum.authentication.base import AuthenticationConsumer
from forum.authentication.base import ConsumerTemplateContext
from forum.authentication.base import InvalidAuthentication

from forum.models.user import AuthKeyUserAssociation

CLIENT_SECRETS_PATH = os.path.join(django_settings.SITE_SRC_ROOT,
                                   'client_secrets.json')
CLIENT_SECRETS = json.loads(open(CLIENT_SECRETS_PATH, 'r').read())
CLIENT_ID = CLIENT_SECRETS['web']['client_id']


class GooglePlusAuthConsumer(AuthenticationConsumer):

    @staticmethod
    def _generate_random_state():
        """
        Generates a random string with length of 32 symbols, used by the
        Google+ API to prevent request forgery.
        """
        symbols = string.ascii_lowercase + string.digits
        state = ''.join(random.choice(symbols) for _ in range(32))
        return state

    def prepare_authentication_request(self, request, redirect_to):
        """
        Prepares the Google+ authentication URL and adds needed parameters
        to it, like scopes, the generated state, client ID, etc.
        """
        state = self._generate_random_state()
        scopes = (
            "https://www.googleapis.com/auth/plus.login",
            "https://www.googleapis.com/auth/plus.profile.emails.read"
        )
        request.session['gplus_state'] = state
        request_data = dict(
            redirect_uri="{0}{1}".format(django_settings.APP_URL, redirect_to),
            scope="  ".join(scopes),
            state=state,
            response_type="code",
            client_id=CLIENT_ID,
            access_type="offline"
        )

        # Send also openid.realm to get the necessary data to convert from the
        # old OpenID to Google+
        realm = getattr(django_settings, 'OPENID_TRUST_ROOT',
                        django_settings.APP_URL+'/')
        request_data["openid.realm"] = realm

        login_url = 'https://accounts.google.com/o/oauth2/auth?{0}'.format(
            urllib.urlencode(request_data)
        )
        return login_url

    def process_authentication_request(self, request):
        """
        Triggered after the Google+ authentication happened. Important
        information from it is extracted, access token and association
        keys are obtained, so that local authentication system could
        process.
        """
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

        # Convert old Google OpenID to Google+
        openid = credentials.id_token['openid_id']
        already_existing = AuthKeyUserAssociation.objects.filter(
            key=assoc_key, provider="googleplus"
        )
        if already_existing.count() == 0:
            try:
                old = AuthKeyUserAssociation.objects.get(key=openid,
                                                         provider="google")
            except AuthKeyUserAssociation.DoesNotExist:
                pass
            else:
                old.key = assoc_key
                old.provider = "googleplus"
                old.save()

        return assoc_key

    def get_user_data(self, assoc_key):
        """
        Returns user data, like username, email and real name. That data
        is forwarded to the sign-up form.
        """
        return {}


class GooglePlusAuthContext(ConsumerTemplateContext):
    mode = 'BIGICON'
    type = 'CUSTOM'
    weight = 100
    human_name = 'Google+'
    code_template = 'modules/gplusauth/button.html'
    extra_css = []
