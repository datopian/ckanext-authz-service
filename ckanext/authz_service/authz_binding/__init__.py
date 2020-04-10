from ..authzzie import Authzzie
from . import dataset as ds
from . import organization as org
from . import resource as res

__all__ = ['default_authz_bindings']


def default_authz_bindings(authorizer):
    # type: (Authzzie) -> None
    """Initialize default authorization bindings for CKAN entities
    """

    # Register organization authz bindings
    authorizer.register_scope_normalizer('org', org.normalize_org_scope)
    authorizer.register_authorizer('org', org.check_org_permissions,
                                   actions=org.ORG_ENTITY_CHECKS.keys() + [None])

    # Register dataset authz bindings
    authorizer.register_entity_ref_parser('ds', ds.dataset_id_parser)
    authorizer.register_authorizer('ds', ds.check_dataset_permissions,
                                   actions=ds.DS_ENTITY_CHECKS.keys() + [None],
                                   subscopes=(None, 'data', 'metadata'))

    # Register resource authz bindings
    authorizer.register_entity_ref_parser('res', res.resource_id_parser)
    authorizer.register_authorizer('res', res.check_resource_permissions,
                                   actions=res.RES_ENTITY_CHECKS.keys() + [None],
                                   subscopes=(None, 'data', 'metadata'))
