"""CKAN API actions
"""
import random
import string
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import jwt
import pytz
from ckan.plugins import toolkit
from six import string_types
from six.moves import range

from . import util
from .authzzie import Scope


def authorize(authzzie, context, data_dict):
    """Request an authorization token for a list of scopes

    TODO: allow requesting expiration time
    """
    scopes = toolkit.get_or_bust(data_dict, 'scopes')
    if isinstance(scopes, string_types):
        scopes = scopes.split(' ')
    requested_scopes = [Scope.from_string(s) for s in scopes]
    granted_permissions = {str(s): list(authzzie.get_permissions(s))
                           for s in requested_scopes}

    lifetime = 900  # TODO: should default to config + be dynamic
    user = context.get('auth_user_obj')
    print(user)
    return {"user_id": user.name,
            "token": _create_token(user, granted_permissions, lifetime),
            "expires_at": datetime.now().isoformat(),
            "requested_scopes": scopes,
            "granted": granted_permissions}


@toolkit.side_effect_free
def verify(_, data_dict, **__):
    """Validate a JWT token and dump it's payload
    """
    token = toolkit.get_or_bust(data_dict, 'token')
    strict = toolkit.asbool(data_dict.get('strict', True))
    jwt_algorithm = util.get_config('jwt_algorithm', 'RS256')
    if jwt_algorithm[0:2] == 'HS':
        # We're using a symmetric secret key
        key = _get_private_key()
    else:
        key = _get_public_key()

    if key is None:
        raise ValueError("No key is configured to verify JWT token")

    try:
        decoded = jwt.decode(token, key, algorithms=jwt_algorithm)
        result = {"verified": jwt.decode,
                  "payload": decoded}
    except jwt.PyJWTError as e:
        result = {"verified": False,
                  "message": str(e)}

        if not strict:
            # Try to decode without verification and provide the payload
            try:
                decoded = jwt.decode(token, key, verify=False, algorithms=jwt_algorithm)
                result['payload'] = decoded
            except jwt.PyJWTError:
                pass

    return result


@toolkit.side_effect_free
def public_key(*_, **__):
    """Provide the public key used for JWT signing, if one was configured
    """
    pub_key = _get_public_key()
    if pub_key:
        return {
            "public_key": pub_key
        }

    raise toolkit.ObjectNotFound("Public key has not been configured")


def _create_token(user, scopes, lifetime):
    # type: (Dict, List, int) -> str
    """Create a JWT token
    """
    jwt_algorithm = util.get_config('jwt_algorithm', 'RS256')

    private_key = _get_private_key()
    if not private_key:
        raise ValueError("JWT secret key is not configured")

    issuer = util.get_config('jwt_issuer', toolkit.config.get('ckan.site_url'))
    audience = util.get_config('jwt_audience', issuer)
    payload = {"exp": datetime.now(tz=pytz.utc) + timedelta(seconds=lifetime),
               "nbf": datetime.now(tz=pytz.utc),
               "sub": user.name,
               "aud": audience,
               "iss": issuer,
               "name": user.fullname,  # The user's name  # TODO: implement
               "scopes": ' '.join(str(s) for s in scopes)}

    if util.get_config_bool('jwt_include_user_email', False):
        payload['email'] = user.email

    if util.get_config_bool('jwt_include_token_id', False):
        payload['jti'] = _generate_jti()

    return jwt.encode(payload, private_key, jwt_algorithm)


def _get_public_key():
    # type: () -> Optional[str]
    """Get the configured public key from file
    """
    pub_key_file = util.get_config('jwt_public_key_file', None)
    if pub_key_file is None:
        return None

    with open(pub_key_file, 'r') as f:
        return bytes(f.read())


def _get_private_key():
    # type: () -> Optional[str]
    """Get the configured private key from file or string
    """
    private_key = util.get_config('jwt_private_key', None)
    if not private_key:
        private_key_file = util.get_config('jwt_private_key_file')
        if private_key_file:
            with open(private_key_file, 'r') as f:
                private_key = f.read()
    return private_key


def _generate_jti(length=8):
    # type: (int) -> bytes
    """Generate a unique token ID
    """
    return b''.join(random.choice(string.printable) for _ in range(length))
