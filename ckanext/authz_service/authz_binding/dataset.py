from typing import Dict, Optional, Set

from ckan.plugins import toolkit

from . import common as c
from .common import (OptionalCkanContext, check_entity_permissions, ckan_auth_check, ckan_get_user_role_in_group,
                     ckan_is_sysadmin, normalize_id_part)

DS_ENTITY_CHECKS = {"read": "package_show",
                    "list": None,
                    "create": None,
                    "update": "package_update",
                    "delete": "package_delete",
                    "patch": "package_update",
                    "purge": "dataset_purge"}


def check_dataset_permissions(id, organization_id=None, context=None):
    # type: (str, Optional[str], OptionalCkanContext) -> Set[str]
    """Check what dataset permissions a user has
    """
    if organization_id in {'*', None}:
        return _check_dataset_permissions_unknown_org(id, organization_id, context=context)

    if id in {'*', None}:
        return _check_dataset_permissions_unknown_ds(id, organization_id, context=context)

    if not _check_ds_in_org(id, organization_id, context=context):
        # If user can't see the dataset, we'll assume it exists but no permissions
        return set()

    return check_entity_permissions(DS_ENTITY_CHECKS, {"id": id, "owner_org": organization_id}, context=context)


def _check_dataset_permissions_unknown_org(id, organization_id, context=None):
    # type: (str, Optional[str], OptionalCkanContext) -> Set[str]
    """Run dataset permissions checks when no specific org ID was specified
    """
    if ckan_is_sysadmin(context=context):
        return set(DS_ENTITY_CHECKS.keys())

    if organization_id == '*':
        # Regular users do not get any '*' permissions on any org dataset
        return set()

    # Regular users do not get any global scope permissions on datasets
    if id in {None, '*'}:
        return set()

    # We got a dataset ID with no organization specified
    return check_entity_permissions(DS_ENTITY_CHECKS, {"id": id}, context=context)


def _check_dataset_permissions_unknown_ds(id, organization_id, context=None):
    # type: (Optional[str], str, OptionalCkanContext) -> Set[str]
    """Run dataset permissions checks when dataset ID is not known
    """
    granted = set()
    if ckan_auth_check('package_create', {"owner_org": organization_id}, context=context):
        granted.add('create')

    if ckan_auth_check('package_list', {"owner_org": organization_id}, context=context):
        granted.add('list')

    if id == '*':
        # only grant 'read' by default to org members
        if ckan_get_user_role_in_group(organization_id, context=context):
            granted.add('read')

        if ckan_auth_check('organization_update', {"id": organization_id}, context=context):
            granted.update({'update', 'patch'})

        if ckan_auth_check('organization_delete', {"id": organization_id}, context=context):
            granted.update('delete')

        # TODO: check `delete` and `purge` permissions

    return granted


def dataset_id_parser(id):
    # type: (str) -> Dict[str, Optional[str]]
    """ID parser for dataset entities

    Some examples of the types of IDs accepted and parsed by this function:

    >>> dataset_id_parser('foo/bar')
    {'organization_id': 'foo', 'id': 'bar'}

    >>> dataset_id_parser('bar')
    {'id': 'bar'}

    >>> dataset_id_parser('foo/bar/baz')
    {'organization_id': 'foo', 'id': 'bar/baz'}

    >>> dataset_id_parser('foo/*')
    {'organization_id': 'foo', 'id': '*'}

    >>> dataset_id_parser('foo/')
    {'organization_id': 'foo', 'id': None}
    """
    parts = id.split('/', 1)
    if len(parts) == 1:
        return {"id": parts[0]}
    return {"organization_id": parts[0],
            "id": normalize_id_part(parts[1])}


def _check_ds_in_org(id, organization_id, context=None):
    # type: (str, str, OptionalCkanContext) -> bool
    """Check that a dataset exists in the given organization and that it is readable
    """
    if context is None:
        context = c.get_user_context()
    try:
        ds = toolkit.get_action('package_show')(context, {"id": id})
        if ds.get('owner_org') == organization_id or ds.get('organization', {}).get('name') == organization_id:
            return True
    except (toolkit.ObjectNotFound, toolkit.NotAuthorized):
        pass

    return False
