"""Alias of `factory.config` -- see agent_factory/__init__.py."""

import sys

from factory import config as _config

sys.modules[__name__] = _config
