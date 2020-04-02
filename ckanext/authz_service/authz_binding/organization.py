"""Authorization bindings for organizations
"""
from typing import Optional, Set

from ..authzzie import Scope
from .common import (authzzie, check_entity_permissions, ckan_auth_check,
                     ckan_is_sysadmin)

ORG_ENTITY_CHECKS = {"read": "organization_show",
                     "list": None,
                     "create": None,
                     "update": "organization_update",
                     "delete": "organization_delete",
                     "patch": "organization_patch",
                     "purge": "organization_purge"}


@authzzie.authorizer('org', actions=ORG_ENTITY_CHECKS.keys() + [None])
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


@authzzie.scope_normalizer('org')
def normalize_org_scope(requested, granted, *_, **__):
    # type: (Scope, Scope) -> Scope
    """Normalize an org granted scope
    """
    if requested.actions is None and requested.entity_ref not in {None, '*'}:
        # User requested all actions on a specific org
        if granted.actions == set(k for k, v in ORG_ENTITY_CHECKS.items() if v is not None):
            granted.actions = '*'

    return granted
