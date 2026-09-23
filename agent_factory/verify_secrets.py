"""Alias of `factory.verify_secrets` -- see agent_factory/__init__.py."""

import sys

from factory import verify_secrets as _verify_secrets

sys.modules[__name__] = _verify_secrets
