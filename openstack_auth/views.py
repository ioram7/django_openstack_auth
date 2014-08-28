# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import json

from lxml import html

import django
from django.conf import settings
from django.contrib import auth
from django.contrib.auth.decorators import login_required  # noqa
from django.contrib.auth import views as django_auth_views
from django import shortcuts
from django.http import response
import requests
from django.template import response as t_response
from django.utils import functional
from django.utils import http
from django.views.decorators.cache import never_cache  # noqa
from django.views.decorators.csrf import csrf_protect  # noqa
from django.views.decorators.debug import sensitive_post_parameters  # noqa

from keystoneclient import exceptions as keystone_exceptions
from keystoneclient.v2_0 import client as keystone_client_v2
from keystoneclient.v3 import client as keystone_client_v3
from keystoneclient import access
from keystoneclient import session
from keystoneclient.contrib.auth.v3 import saml2

from openstack_auth import forms
# This is historic and is added back in to not break older versions of
# Horizon, fix to Horizon to remove this requirement was committed in
# Juno
from openstack_auth.forms import Login  # noqa
from openstack_auth import user as auth_user
from openstack_auth import backend
from openstack_auth import utils

try:
    is_safe_url = http.is_safe_url
except AttributeError:
    is_safe_url = utils.is_safe_url


LOG = logging.getLogger(__name__)


@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request):
    """Logs a user in using the :class:`~openstack_auth.forms.Login` form."""
    # If the user is already authenticated, redirect them to the
    # dashboard straight away, unless the 'next' parameter is set as it
    # usually indicates requesting access to a page that requires different
    # permissions.
    if (request.user.is_authenticated() and
            auth.REDIRECT_FIELD_NAME not in request.GET and
            auth.REDIRECT_FIELD_NAME not in request.POST):
        return shortcuts.redirect(settings.LOGIN_REDIRECT_URL)

    # Get our initial region for the form.
    initial = {}
    current_region = request.session.get('region_endpoint', None)
    requested_region = request.GET.get('region', None)
    regions = dict(getattr(settings, "AVAILABLE_REGIONS", []))
    if requested_region in regions and requested_region != current_region:
        initial.update({'region': requested_region})

    if request.method == "POST":
        # NOTE(saschpe): Since https://code.djangoproject.com/ticket/15198,
        # the 'request' object is passed directly to AuthenticationForm in
        # django.contrib.auth.views#login:
        if django.VERSION >= (1, 6):
            form = functional.curry(forms.Login)
        else:
            form = functional.curry(forms.Login, request)
    else:
        form = functional.curry(forms.Login, initial=initial)

    extra_context = {'redirect_field_name': auth.REDIRECT_FIELD_NAME}

    if request.is_ajax():
        template_name = 'auth/_login.html'
        extra_context['hide'] = True
    else:
        template_name = 'auth/login.html'

    res = django_auth_views.login(request,
                                  template_name=template_name,
                                  authentication_form=form,
                                  extra_context=extra_context)
    # Set the session data here because django's session key rotation
    # will erase it if we set it earlier.
    if request.user.is_authenticated():
        auth_user.set_session_from_user(request, request.user)
        regions = dict(forms.Login.get_region_choices())
        region = request.user.endpoint
        region_name = regions.get(region)
        request.session['region_endpoint'] = region
        request.session['region_name'] = region_name
    return res

def fed_login(request):
    if request.GET.get("token") is None:
        idp = json.loads(request.POST.get('identity_provider'))['id']
        redirect = settings.OPENSTACK_KEYSTONE_FEDERATED_URL+'/OS-FEDERATION/identity_providers/'+idp+'/protocols/saml2/auth'
        referral =("?refer_to="+request.get_host()+"/auth/fed_login")
        return response.HttpResponseRedirect(redirect+referral)
    else:
        projects = requests.get(settings.OPENSTACK_KEYSTONE_FEDERATED_URL+'/OS-FEDERATION/projects', headers={'X-Auth-Token':request.GET.get('token')})
        projects = json.loads(projects.text)["projects"]
        form = forms.FederatedProjectForm(projects, request.GET.get('token'))
        #return shortcuts.render(request, 'auth/_fed_projects.html', {'form':form})
        return t_response.TemplateResponse(request, 'auth/_fed_projects.html', {'projects':projects, 'token': request.GET.get('token')})

def fed_projects(request):
    projects = json.dumps(request.POST.get('projects'))
    print "Projects: %s" % projects[0]
    scope = {'project':{'id': request.POST.get('project')}}
    identity = {'methods':['saml2'], 'saml2':{'id': request.POST.get('token')}}
    setattr(request.session, '_unscopedtoken', request.POST.get('token'))
    auth_payload = {'auth':{'identity':identity, 'scope':scope}}
    headers = {'Content-Type':'application/json', 'X-Auth-Token': request.POST.get('token')}
    r = requests.post(settings.OPENSTACK_KEYSTONE_FEDERATED_URL+'/auth/tokens', headers=headers, data=json.dumps(auth_payload))
    token_data = json.loads(r.text)
    token_id = r.headers.get('X-Subject-Token')
    token_data = token_data.get('token')
    regions = dict(forms.Login.get_region_choices())
    region = settings.OPENSTACK_KEYSTONE_FEDERATED_URL
    region_name = regions.get(region)
    token = access.AccessInfo.factory(body=json.loads(r.text), resp=r, region_name=region_name)
    request.session['token'] = token
    project = request.POST.get('project')
    plugin = saml2.Saml2ScopedToken(settings.OPENSTACK_KEYSTONE_FEDERATED_URL, request.POST.get('token'), project_id=project)
    sess = session.Session(plugin)
    try:
        client = keystone_client_v3.Client(auth_ref=token, session=sess)
    except Exception as e:
        print e
    auth_ref = client.auth_ref
    token = auth_user.Token(auth_ref)
    user = auth_user.create_user_from_token(request, token, settings.OPENSTACK_KEYSTONE_FEDERATED_URL)
    user.authorized_tenants = projects
    auth_user.set_session_from_user(request, user)
    
    request.session[auth.SESSION_KEY] = user.id
    request.session[auth.BACKEND_SESSION_KEY] = 'openstack_auth.backend.KeystoneBackend'
    setattr(request, '_keystoneclient', client)
    return login(request)

def logout(request):
    msg = 'Logging out user "%(username)s".' % \
        {'username': request.user.username}
    LOG.info(msg)
    endpoint = request.session.get('region_endpoint')
    token = request.session.get('token')
    if token and endpoint:
        delete_token(endpoint=endpoint, token_id=token.id)
    """ Securely logs a user out. """
    return django_auth_views.logout_then_login(request)


def delete_token(endpoint, token_id):
    """Delete a token."""

    insecure = getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False)
    ca_cert = getattr(settings, "OPENSTACK_SSL_CACERT", None)
    utils.remove_project_cache(token_id)
    try:
        if utils.get_keystone_version() < 3:
            client = keystone_client_v2.Client(
                endpoint=endpoint,
                token=token_id,
                insecure=insecure,
                cacert=ca_cert,
                debug=settings.DEBUG
            )
            client.tokens.delete(token=token_id)
            LOG.info('Deleted token %s' % token_id)
        else:
            # FIXME: KS-client does not have delete token available
            # Need to add this later when it is exposed.
            pass
    except keystone_exceptions.ClientException:
        LOG.info('Could not delete token')


@login_required
def switch(request, tenant_id, redirect_field_name=auth.REDIRECT_FIELD_NAME):
    """Switches an authenticated user from one project to another."""
    LOG.debug('Switching to tenant %s for user "%s".'
              % (tenant_id, request.user.username))
    insecure = getattr(settings, 'OPENSTACK_SSL_NO_VERIFY', False)
    ca_cert = getattr(settings, "OPENSTACK_SSL_CACERT", None)
    endpoint = request.user.endpoint
    try:
        if utils.get_keystone_version() >= 3:
            if 'v3' not in endpoint:
                endpoint = endpoint.replace('v2.0', 'v3')
        client = utils.get_keystone_client().Client(
            tenant_id=tenant_id,
            token=request.user.token.id,
            auth_url=endpoint,
            insecure=insecure,
            cacert=ca_cert,
            debug=settings.DEBUG)
        auth_ref = client.auth_ref
        msg = 'Project switch successful for user "%(username)s".' % \
            {'username': request.user.username}
        LOG.info(msg)
    except keystone_exceptions.ClientException:
        msg = 'Project switch failed for user "%(username)s".' % \
            {'username': request.user.username}
        LOG.warning(msg)
        auth_ref = None
        LOG.exception('An error occurred while switching sessions.')

    # Ensure the user-originating redirection url is safe.
    # Taken from django.contrib.auth.views.login()
    redirect_to = request.REQUEST.get(redirect_field_name, '')
    if not is_safe_url(url=redirect_to, host=request.get_host()):
        redirect_to = settings.LOGIN_REDIRECT_URL

    if auth_ref:
        old_endpoint = request.session.get('region_endpoint')
        old_token = request.session.get('token')
        if old_token and old_endpoint and old_token.id != auth_ref.auth_token:
            delete_token(endpoint=old_endpoint, token_id=old_token.id)
        user = auth_user.create_user_from_token(
            request, auth_user.Token(auth_ref), endpoint)
        auth_user.set_session_from_user(request, user)
    return shortcuts.redirect(redirect_to)


@login_required
def switch_region(request, region_name,
                  redirect_field_name=auth.REDIRECT_FIELD_NAME):
    """Switches the user's region for all services except Identity service.

    The region will be switched if the given region is one of the regions
    available for the scoped project. Otherwise the region is not switched.
    """
    if region_name in request.user.available_services_regions:
        request.session['services_region'] = region_name
        LOG.debug('Switching services region to %s for user "%s".'
                  % (region_name, request.user.username))

    redirect_to = request.REQUEST.get(redirect_field_name, '')
    if not is_safe_url(url=redirect_to, host=request.get_host()):
        redirect_to = settings.LOGIN_REDIRECT_URL

    return shortcuts.redirect(redirect_to)
