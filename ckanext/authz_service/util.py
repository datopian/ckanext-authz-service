"""Useful utility functions
"""
from typing import Any, Optional

import ckan.plugins.toolkit as toolkit

CONFIG_PREFIX = __package__


def get_config(key, default=None):
    # type: (str, Optional[Any]) -> Optional[str]
    """Get configuration option for this CKAN plugin
    """
    return toolkit.config.get('{}.{}'.format(CONFIG_PREFIX, key), default)


def get_config_bool(key, default=False):
    # type: (str, bool) -> bool
    """Get a boolean configuration option for this CKAN plugin
    """
    return toolkit.asbool(get_config(key, default))


def get_config_int(key, default=0):
    # type: (str, int) -> int
    """Get an integer configuration option for this CKAN plugin
    """
    return toolkit.asint(get_config(key, default))
