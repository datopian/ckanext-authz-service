from ckan.tests import helpers

from ckanext.authz_service import util


class TestConfigUtils(object):

    @helpers.change_config('ckanext.authz_service.foo_option', 'bar')
    def test_get_config_returns_str(self):
        assert util.get_config('foo_option') == 'bar'

    def test_get_config_returns_default(self):
        assert util.get_config('foo_option', 'bazz') == 'bazz'

    def test_get_config_returns_none_by_default(self):
        assert util.get_config('foo_option') is None

    @helpers.change_config('ckanext.authz_service.foo_option', '3')
    def test_get_config_int_returns_int(self):
        assert util.get_config_int('foo_option') == 3

    def test_get_config_int_returns_default(self):
        assert util.get_config_int('foo_option', 5) == 5

    @helpers.change_config('ckanext.authz_service.foo_option', 'true')
    def test_get_config_bool_returns_bool(self):
        assert util.get_config_bool('foo_option') is True

    @helpers.change_config('ckanext.authz_service.foo_option', 'false')
    def test_get_config_bool_returns_bool_false(self):
        assert util.get_config_bool('foo_option', True) is False

    def test_get_config_bool_returns_false_by_default(self):
        assert util.get_config_bool('foo_option') is False

    def test_get_config_bool_returns_default(self):
        assert util.get_config_bool('foo_option', True) is True
