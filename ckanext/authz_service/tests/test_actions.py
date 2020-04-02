import jwt
from ckan.plugins import toolkit
from ckan.tests import factories, helpers
from nose.tools import assert_equals, assert_raises, assert_true

from . import FunctionalTestBase, temporary_file, user_context

# RSA public key for testing purposes
RSA_PUB_KEY = """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwa1W4fb4CgFH5EXsLlJI
Vr+r2ZB17hR4mXNhJhj4hXm4UQlC6Rnjc1MJ1fse3ClkaD5GFbGfwnDr2iXMaoBo
v2F1mZR4TG/5muIEUEwUg2t5z/CBfYMIGG3Fucg9Et2rmc2MQPCPnN5H8XvzCgE4
Wa662tMtGZmM1FtKtMVEM3MRo4rHNS4wcl+SPoKLgAOgWQtIMVy0AYyldRfBVG3+
vrB4Y++leN8DZZrLYALL93WmMiaZE9Al8rndTte5gIaLJ2cnHXL8KEw6JPBXwP92
QEIzFlh0Nbt0FSRnX9wrJovJikTeMWD75zevGP5I4Oag0oiARVh5iZHNsEYki2dC
XOX01Eqh2ZXwuqOUon5RAaJesdbGz5M6G1zY5CTZ7tzgiDkl1vl0PC12J8XmfTda
pg8OxHi9EI8caqIqATaExSMFSFs+OxEog8vv+DifQfVzCxyGiOkw81NRPw46Qylf
UBaeSYhylc2KRLuMRfVLT5HMLzG7QJ0jinkaUKGJznCzEqynxa187Ar1Z+SDZ07g
q54mfdM9B6eS/SEbJhFI9oRFv9BSlo8YXfzLHOdXwrmWZDZmzTKfAtQKY9luSfrL
8Fe0+w4kGtQ5PLXEe7NWCSS9oXnVAs7/cNxqaKNHF8gj39iBvJdyVdqsMHtXdyvz
ZK4b9J6UQSKjmNaLu8EuVi8CAwEAAQ==
-----END PUBLIC KEY-----
"""


class TestAuthorizeAction(FunctionalTestBase):
    """Test cases for the default authorization binding defined in the extension
    for datasets
    """

    def setup(self):

        super(TestAuthorizeAction, self).setup()

        self.org_admin = factories.User()
        self.org_member = factories.User()
        self.org = factories.Organization(
            users=[
                {'name': self.org_member['name'], 'capacity': 'member'},
                {'name': self.org_admin['name'], 'capacity': 'admin'},
            ]
        )

    def test_authorize_request_full_org_access(self):
        """Test some basic authorize request
        """
        scopes = ['org:{}:*'.format(self.org['name'])]
        with user_context(self.org_admin) as context:
            result = helpers.call_action(
                'authz_authorize',
                context,
                scopes=scopes)

        normalized_scopes = ['org:{}'.format(self.org['name'])]
        assert_equals(result['requested_scopes'], normalized_scopes)
        assert_equals(result['granted_scopes'], normalized_scopes)
        assert_equals(result['user_id'], self.org_admin['name'])

    def test_authorize_raises_on_unknown_entity(self):
        """Test that authorize does not accept unknown entity types
        """
        sysadmin = factories.Sysadmin()
        with user_context(sysadmin) as context:
            assert_raises(toolkit.ValidationError, helpers.call_action,
                          'authz_authorize', context,
                          scopes=['spam:*'])


class TestPublicKeyAction(FunctionalTestBase):

    def test_public_key_is_available(self):
        """Test that public key is returned properly
        """
        with temporary_file(RSA_PUB_KEY) as pub_key_file, \
                helpers.changed_config('ckanext.authz_service.jwt_public_key_file', pub_key_file):
            result = helpers.call_action('authz_public_key', {})

        assert_equals(result['public_key'], RSA_PUB_KEY)

    def test_public_key_not_configured_throws(self):
        """Test that when no public key is configured, ObjectNotFound is raised
        """
        assert_raises(toolkit.ObjectNotFound, helpers.call_action,
                      'authz_public_key', {})


class TestJwtConfig(FunctionalTestBase):
    """Various tests that verify the effect of JWT configuration on actions
    """

    def setup(self):
        super(TestJwtConfig, self).setup()

        self.user = factories.User(email='some-user@example.com')
        self.org = factories.Organization(
            users=[
                {'name': self.user['name'], 'capacity': 'admin'},
            ]
        )

    @helpers.change_config('ckanext.authz_service.jwt_include_token_id', True)
    def test_jwt_generated_with_jti(self):
        """Test that JWT includes `jti` when token ID is enabled
        """
        scopes = ['org:{}:*'.format(self.org['name'])]
        with user_context(self.user) as context:
            result = helpers.call_action(
                'authz_authorize',
                context,
                scopes=scopes)

        assert_equals(result['user_id'], self.user['name'])
        jwt_payload = _decode_jwt(result['token'])
        assert_true(jwt_payload['jti'])

    @helpers.change_config('ckanext.authz_service.jwt_include_user_email', True)
    def test_jwt_includes_email(self):
        """Test that JWT includes `jti` when token ID is enabled
        """
        scopes = ['org:{}:*'.format(self.org['name'])]
        with user_context(self.user) as context:
            result = helpers.call_action(
                'authz_authorize',
                context,
                scopes=scopes)

        assert_equals(result['user_id'], self.user['name'])
        jwt_payload = _decode_jwt(result['token'])
        assert_equals(jwt_payload['email'], self.user['email'])


def _decode_jwt(token):
    """Decode a JWT token generated by the system

    Because we are in test mode, JWT tokens are simply base64 encoded JSON
    """
    return jwt.decode(token, None, verify=False, algorithms=['none'])
