"""Alias of `factory.deploy` -- see agent_factory/__init__.py."""

import sys

from factory import deploy as _deploy

sys.modules[__name__] = _deploy
