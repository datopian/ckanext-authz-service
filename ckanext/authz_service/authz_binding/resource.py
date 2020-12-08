from typing import Dict, Optional

from ckan.plugins import toolkit

from .common import check_entity_permissions, get_user_context, normalize_id_part
from .dataset import check_dataset_permissions

RES_ENTITY_CHECKS = {"read": "resource_show",
                     "create": None,
                     "update": "resource_update",
                     "delete": "resource_delete"}


def check_resource_permissions(id, dataset_id=None, organization_id=None):
    """Check what resource permissions a user has
    """
    if dataset_id is None:
        return set()

    granted = check_dataset_permissions(id=dataset_id, organization_id=organization_id)
    if id == '*' or id is None:
        # Resource permissions for "all resources" can be taken from dataset permissions
        return granted.intersection(set(RES_ENTITY_CHECKS.keys()))

    if not _check_resource_in_dataset(id, dataset_id):
        return set()

    return check_entity_permissions(RES_ENTITY_CHECKS, {"id": id})


def resource_id_parser(id):
    # type: (str) -> Dict[str, Optional[str]]
    """ID parser for resource entities

    Some examples of the types of IDs accepted and parsed by this function:

    >>> resource_id_parser('foo/bar/baz')
    {'organization_id': 'foo', 'dataset_id': 'bar', 'id': 'baz'}

    >>> resource_id_parser('baz')
    {'id': 'baz'}

    >>> resource_id_parser('foo/bar/')
    {'organization_id': 'foo', 'dataset_id': 'bar', 'id': None}

    >>> resource_id_parser('foo/*/')
    {'organization_id': 'foo', 'dataset_id': '*', 'id': None}

    >>> resource_id_parser('foo/*/*')
    {'organization_id': 'foo', 'dataset_id': '*', 'id': '*'}

    >>> resource_id_parser('foo//')
    {'organization_id': 'foo', 'dataset_id': None, 'id': None}

    The following ID structure will not be accepted:

    >>> resource_id_parser('foo/bar')
    Traceback (most recent call last):
      ...
    ValueError: Unexpected resource ID structure: foo/bar
    """
    parts = id.split('/', 2)
    if len(parts) == 1:
        return {"id": parts[0]}
    elif len(parts) == 2:
        raise ValueError("Unexpected resource ID structure: {}".format(id))
    return {"organization_id": parts[0],
            "dataset_id": normalize_id_part(parts[1]),
            "id": normalize_id_part(parts[2])}


def _check_resource_in_dataset(resource_id, dataset_id):
    # type: (str, str) -> bool
    """Check that a resource exists in the dataset
    """
    try:
        ds = toolkit.get_action('package_show')(get_user_context(), {"id": dataset_id})
        for resource in ds['resources']:
            if resource['id'] == resource_id:
                return True
    except (toolkit.ObjectNotFound, toolkit.NotAuthorized):
        pass

    return False
