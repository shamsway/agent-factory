"""Alias of `factory.dispatch` -- see agent_factory/__init__.py."""

import sys

from factory import dispatch as _dispatch

sys.modules[__name__] = _dispatch
