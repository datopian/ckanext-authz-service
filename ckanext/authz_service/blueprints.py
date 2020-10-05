"""ckanext-authz-service Flask blueprints
"""
from ckan.plugins import toolkit
from flask import Blueprint, Response

blueprint = Blueprint(
    'authz_service',
    __name__,
)


def public_key():
    """Get the public key used to verify JWT tokens signed by us

    If no public key has been configured (e.g. we are using a symmetric algorithm), will
    return 204 with no content.
    """
    try:
        pub_key = toolkit.get_action('authz_public_key')(None, {}).get('public_key')
    except (toolkit.ObjectNotFound, AttributeError, KeyError):
        pub_key = None

    if not pub_key:
        return '', 204, {"Content-type": None}

    return Response(pub_key, mimetype='application/x-pem-file')


blueprint.add_url_rule(u'/authz/public_key', view_func=public_key)
