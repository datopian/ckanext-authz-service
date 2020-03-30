from typing import Dict, Optional

from .common import authzzie, normalize_id_part


@authzzie.id_parser('res')
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
