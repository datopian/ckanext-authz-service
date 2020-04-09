from functools import partial

import ckan.plugins as plugins

from ckanext.authz_service import actions
from ckanext.authz_service.authz_binding import default_authz_bindings
from ckanext.authz_service.authzzie import Authzzie
from ckanext.authz_service.interfaces import IAuthorizationBindings


class AuthzServicePlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IActions)
    plugins.implements(IAuthorizationBindings)

    # IActions

    def get_actions(self):
        authorizer = init_authorizer()
        return {'authz_authorize': partial(actions.authorize, authorizer),
                'authz_verify': actions.verify,
                'authz_public_key': actions.public_key}

    def register_authz_bindings(self, authorizer):
        default_authz_bindings(authorizer)


def init_authorizer():
    authorizer = Authzzie()
    for plugin in plugins.PluginImplementations(IAuthorizationBindings):
        if hasattr(plugin, 'register_authz_bindings'):
            plugin.register_authz_bindings(authorizer)

    return authorizer
