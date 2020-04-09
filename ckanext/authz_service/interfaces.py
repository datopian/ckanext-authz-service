"""CKAN plugin interface
"""
from ckan.plugins import Interface

from .authzzie import Authzzie


class IAuthorizationBindings(Interface):

    """A CKAN plugin interface for providing new authorization
    bindings or overriding existing ones
    """

    def register_authz_bindings(self, authorizer):
        # type: (Authzzie) -> None
        pass
