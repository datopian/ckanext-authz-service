"""CKAN API actions
"""
import random
import string
from datetime import datetime, timedelta
from typing import List, Optional

import jwt
import pytz
from ckan.model.user import User
from ckan.plugins import toolkit

from . import util
from .authzzie import Scope, UnknownEntityType

DEFAULT_MAX_LIFETIME = 900


def authorize(authorizer, context, data_dict):
    """Request an authorization token for a list of scopes
    """
    scopes = toolkit.get_or_bust(data_dict, 'scopes')
    if isinstance(scopes, str):
        scopes = scopes.split(' ')
    requested_scopes = [Scope.from_string(s) for s in scopes]

    max_lifetime = util.get_config_int('jwt_max_lifetime', DEFAULT_MAX_LIFETIME)
    lifetime = min(toolkit.asint(data_dict.get('lifetime', max_lifetime)), max_lifetime)
    expires = datetime.now(tz=pytz.utc) + timedelta(seconds=lifetime)

    try:
        granted_scopes = [str(scope) for scope
                          in filter(None, (authorizer.authorize_scope(s, context=context) for s in requested_scopes))]
    except UnknownEntityType as e:
        raise toolkit.ValidationError(str(e))

    user = context.get('auth_user_obj')
    return {"user_id": user.name if user else None,
            "token": _create_token(user, granted_scopes, expires),
            "expires_at": expires.isoformat(),
            "requested_scopes": [str(s) for s in requested_scopes],
            "granted_scopes": granted_scopes}


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
        result = {"verified": True,
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


def _create_token(user, scopes, expires):
    # type: (Optional[User], List[Scope], datetime) -> str
    """Create a JWT token
    """
    jwt_algorithm = util.get_config('jwt_algorithm', 'RS256')
    private_key = _get_private_key()
    issuer = util.get_config('jwt_issuer', toolkit.config.get('ckan.site_url'))

    payload = {"exp": expires,
               "nbf": datetime.now(tz=pytz.utc),
               "sub": user.name if user else None,
               "iss": issuer,
               "name": user.fullname if user else None,
               "scopes": ' '.join(scopes)}

    audience = util.get_config('jwt_audience')
    if audience:
        payload['aud'] = audience

    if util.get_config_bool('jwt_include_user_email', False):
        payload['email'] = user.email if user else None

    if util.get_config_bool('jwt_include_token_id', False):
        payload['jti'] = _generate_jti()

    return jwt.encode(payload, private_key, jwt_algorithm)


def _get_public_key():
    # type: () -> Optional[bytes]
    """Get the configured public key from file
    """
    pub_key_file = util.get_config('jwt_public_key_file', None)
    if pub_key_file is None:
        return None

    with open(pub_key_file, 'rb') as f:
        return f.read()


def _get_private_key():
    # type: () -> Optional[bytes]
    """Get the configured private key from file or string
    """
    private_key = util.get_config('jwt_private_key', None)
    if private_key:
        return private_key.encode('ascii')

    private_key_file = util.get_config('jwt_private_key_file')
    if private_key_file:
        with open(private_key_file, 'rb') as f:
            return f.read()

    return None


def _generate_jti(length=8):
    # type: (int) -> bytes
    """Generate a unique token ID
    """
    return ''.join(random.choice(string.printable) for _ in range(length))
