from functools import partial

import ckan.plugins as plugins
import pkg_resources
import yaml

from ckanext.jwt_authz_api import actions, util
from ckanext.jwt_authz_api.authz_helpers import ckan_auth_wrapper
from ckanext.jwt_authz_api.authzzie import Authzzie


class JwtAuthzApiPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IActions)

    # IActions

    def get_actions(self):
        authzzie = init_authzzie()
        authorize = partial(actions.authorize, authzzie)

        return {'authz_authorize': authorize,
                'authz_verify': actions.verify,
                'authz_public_key': actions.public_key}


def init_authzzie():
    default_map_file = pkg_resources.resource_filename(__name__, 'default-permissions-map.yaml')
    permissions_map_file = util.get_config('permissions_map_file', default_map_file)
    with open(permissions_map_file) as f:
        permissions_map = yaml.safe_load(f)

    return Authzzie(permissions_map, ckan_auth_wrapper)
