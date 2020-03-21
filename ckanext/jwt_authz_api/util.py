"""Useful utility functions
"""
import ckan.plugins.toolkit as toolkit

CONFIG_PREFIX = __package__


def get_config(key, default=None):
    """Get configuration option for this CKAN plugin
    """
    return toolkit.config.get('{}.{}'.format(CONFIG_PREFIX, key), default)


def get_config_bool(key, default=False):
    """Get a boolean configuration option for this CKAN plugin
    """
    return toolkit.asbool(get_config(key, default))
