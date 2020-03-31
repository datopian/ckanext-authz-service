import ckan.plugins as plugins

from ckanext.authz_service import actions


class AuthzServicePlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IActions)

    # IActions

    def get_actions(self):
        return {'authz_authorize': actions.authorize,
                'authz_verify': actions.verify,
                'authz_public_key': actions.public_key}
