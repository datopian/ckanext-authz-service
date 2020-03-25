from typing import Dict, Optional

from ckan import model
from ckan.common import g
from ckan.plugins import toolkit


def ckan_auth_wrapper(check, **extra_args):
    # type: (str, Optional[str]) -> bool
    """CKAN auth system wrapper for Authzzie
    """
    context = dict(model=model, user=g.user, auth_user_obj=g.userobj)
    try:
        toolkit.check_access(check, context, data_dict=extra_args)
    except (toolkit.NotAuthorized, toolkit.ObjectNotFound):
        return False
    return True


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
            "id": _normalize_id_part(parts[1])}


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
            "dataset_id": _normalize_id_part(parts[1]),
            "id": _normalize_id_part(parts[2])}


def _normalize_id_part(id_part):
    # type: (str) -> Optional[str]
    """Normalize an ID part
    """
    return id_part if id_part else None
