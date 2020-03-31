"""Authorization bindings for organizations
"""
from typing import Optional, Set

from .common import (authzzie, check_entity_permissions, ckan_auth_check,
                     ckan_is_sysadmin)

ORG_ENTITY_CHECKS = {"read": "organization_show",
                     "list": None,
                     "create": None,
                     "update": "organization_update",
                     "delete": "organization_delete",
                     "patch": "organization_patch",
                     "purge": "organization_purge"}


@authzzie.auth_check('org', actions=ORG_ENTITY_CHECKS.keys() + [None])
def check_org_permissions(id):
    # type: (str, Optional[str]) -> Set[str]
    """Check what org permissions a user has
    """
    if ckan_is_sysadmin():
        # Sysadmins can do anything, including "any entity" actions
        return set(ORG_ENTITY_CHECKS.keys())
    elif id == '*':
        # Regular users do not get any '*' permissions on orgs
        return set()

    granted = set()
    if id is None:
        # Check if user can perform global actions on organizations
        if ckan_auth_check('organization_list'):
            granted.add('list')

        if ckan_auth_check('organization_create'):
            granted.add('create')

    else:
        granted.update(check_entity_permissions(ORG_ENTITY_CHECKS, {"id": id}))

    return granted
