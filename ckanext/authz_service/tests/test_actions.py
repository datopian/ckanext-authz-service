import jwt
import pytest
from ckan.plugins import toolkit
from ckan.tests import factories, helpers
from ckan.tests.helpers import FunctionalTestBase

from . import ANONYMOUS_USER, temporary_file, user_context

# RSA public key for testing purposes
RSA_PUB_KEY = ("-----BEGIN PUBLIC KEY-----\n"
               "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwa1W4fb4CgFH5EXsLlJI\n"
               "Vr+r2ZB17hR4mXNhJhj4hXm4UQlC6Rnjc1MJ1fse3ClkaD5GFbGfwnDr2iXMaoBo\n"
               "v2F1mZR4TG/5muIEUEwUg2t5z/CBfYMIGG3Fucg9Et2rmc2MQPCPnN5H8XvzCgE4\n"
               "Wa662tMtGZmM1FtKtMVEM3MRo4rHNS4wcl+SPoKLgAOgWQtIMVy0AYyldRfBVG3+\n"
               "vrB4Y++leN8DZZrLYALL93WmMiaZE9Al8rndTte5gIaLJ2cnHXL8KEw6JPBXwP92\n"
               "QEIzFlh0Nbt0FSRnX9wrJovJikTeMWD75zevGP5I4Oag0oiARVh5iZHNsEYki2dC\n"
               "XOX01Eqh2ZXwuqOUon5RAaJesdbGz5M6G1zY5CTZ7tzgiDkl1vl0PC12J8XmfTda\n"
               "pg8OxHi9EI8caqIqATaExSMFSFs+OxEog8vv+DifQfVzCxyGiOkw81NRPw46Qylf\n"
               "UBaeSYhylc2KRLuMRfVLT5HMLzG7QJ0jinkaUKGJznCzEqynxa187Ar1Z+SDZ07g\n"
               "q54mfdM9B6eS/SEbJhFI9oRFv9BSlo8YXfzLHOdXwrmWZDZmzTKfAtQKY9luSfrL\n"
               "8Fe0+w4kGtQ5PLXEe7NWCSS9oXnVAs7/cNxqaKNHF8gj39iBvJdyVdqsMHtXdyvz\n"
               "ZK4b9J6UQSKjmNaLu8EuVi8CAwEAAQ==\n"
               "-----END PUBLIC KEY-----")


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

        assert ['org:{}'.format(self.org['name'])] == result['requested_scopes']
        assert ['org:{}:delete,patch,read,update'.format(self.org['name'])] == result['granted_scopes']
        assert self.org_admin['name'] == result['user_id']

    def test_authorize_raises_on_unknown_entity(self):
        """Test that authorize does not accept unknown entity types
        """
        sysadmin = factories.Sysadmin()
        with user_context(sysadmin) as context:
            with pytest.raises(toolkit.ValidationError):
                helpers.call_action('authz_authorize',
                                    context,
                                    scopes=['spam:*'])

    def test_authorize_request_resource_read_anon_user(self):
        """Test that anonymous users can request to read a public resource
        """
        ds = factories.Dataset(owner_org=self.org['id'])
        scopes = ['res:{}/{}/*:read'.format(self.org['name'], ds['name'])]
        with user_context(ANONYMOUS_USER) as context:
            result = helpers.call_action(
                'authz_authorize',
                context,
                scopes=scopes)

        assert scopes == result['requested_scopes']
        assert scopes == result['granted_scopes']
        assert result['user_id'] is None

    def test_authorize_request_private_resource_read_anon_user(self):
        """Test that anonymous users are denied read access to private resources
        """
        ds = factories.Dataset(owner_org=self.org['id'], private=True)
        scopes = ['res:{}/{}/*:read'.format(self.org['name'], ds['name'])]
        with user_context(ANONYMOUS_USER) as context:
            result = helpers.call_action(
                'authz_authorize',
                context,
                scopes=scopes)

        assert scopes == result['requested_scopes']
        assert [] == result['granted_scopes']
        assert result['user_id'] is None

    def test_authorize_request_resource_write_anon_user(self):
        """Test that anonymous users are denied write access to public resources
        """
        ds = factories.Dataset(owner_org=self.org['id'])
        scopes = ['res:{}/{}/*:write'.format(self.org['name'], ds['name'])]
        with user_context(ANONYMOUS_USER) as context:
            result = helpers.call_action(
                'authz_authorize',
                context,
                scopes=scopes)

        assert scopes == result['requested_scopes']
        assert [] == result['granted_scopes']
        assert result['user_id'] is None


class TestPublicKeyAction(FunctionalTestBase):

    def test_public_key_is_available(self):
        """Test that public key is returned properly
        """
        with temporary_file(RSA_PUB_KEY) as pub_key_file, \
                helpers.changed_config('ckanext.authz_service.jwt_public_key_file', pub_key_file):
            result = helpers.call_action('authz_public_key', {})

        assert RSA_PUB_KEY == result['public_key']

    def test_public_key_not_configured_throws(self):
        """Test that when no public key is configured, ObjectNotFound is raised
        """
        with pytest.raises(toolkit.ObjectNotFound):
            helpers.call_action('authz_public_key', {})


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

        assert self.user['name'] == result['user_id']
        jwt_payload = _decode_jwt(result['token'])
        assert jwt_payload['jti']

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

        assert self.user['name'] == result['user_id']
        jwt_payload = _decode_jwt(result['token'])
        assert self.user['email'] == jwt_payload['email']


def _decode_jwt(token):
    """Decode a JWT token generated by the system

    Because we are in test mode, JWT tokens are simply base64 encoded JSON
    """
    return jwt.decode(token, None, verify=False, algorithms=['none'])
