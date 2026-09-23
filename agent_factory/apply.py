"""Alias of `factory.apply` -- see agent_factory/__init__.py."""

import sys

from factory import apply as _apply

sys.modules[__name__] = _apply
