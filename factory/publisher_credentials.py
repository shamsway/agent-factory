"""Dedicated publisher-owned files and in-memory GitHub App tokens.

Never loads Factory host config, shells, workers, or a shared GitHub credential.
"""
import base64
import json
import os
from pathlib import Path
import re
import stat
import time

from . import investigation_evidence as evidence
from .investigation_publisher import PublisherRefused, http_call


def protected_read(path, *, maximum=32768, secret=False):
    """No symlinks; every ancestor must be owned by root/self and not writable by others."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise PublisherRefused('publisher_policy_invalid')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            meta = os.fstat(fd)
            if meta.st_uid not in {0, os.geteuid()} or meta.st_mode & 0o022:
                raise PublisherRefused('publisher_policy_invalid')
        with evidence.file_at(fd, (path.name,)) as handle:
            meta = os.fstat(handle.fileno())
            # systemd credentials may be root:root 0440 with a service-user ACL.
            # Root-group readability is safe; secret files must never be writable.
            forbidden = 0o337 if secret else 0o022
            if (meta.st_uid not in {0, os.geteuid()} or meta.st_mode & forbidden
                    or (secret and meta.st_mode & 0o040 and meta.st_gid != 0)):
                raise PublisherRefused('publisher_policy_invalid')
            raw = handle.read(maximum + 1)
            if len(raw) > maximum:
                raise PublisherRefused('publisher_policy_invalid')
            return raw
    finally:
        os.close(fd)


def app_policy(raw):
    keys = {'app_id', 'installation_id', 'repository_id', 'repository', 'login', 'key_file'}
    if not isinstance(raw, dict) or set(raw) != keys:
        raise PublisherRefused('publisher_policy_invalid')
    if (any(type(raw[k]) is not int or raw[k] <= 0 for k in ('app_id', 'installation_id', 'repository_id'))
            or not isinstance(raw['repository'], str)
            or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', raw['repository'])
            or not isinstance(raw['login'], str)
            or not re.fullmatch(r'[A-Za-z0-9_-]+\[bot\]', raw['login'])
            or not isinstance(raw['key_file'], str) or not Path(raw['key_file']).is_absolute()):
        raise PublisherRefused('publisher_policy_invalid')
    return dict(raw)


def jwt(p, *, now):
    # Optional dependency stays out of worker/runtime installs until deliberately selected.
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    key = serialization.load_pem_private_key(protected_read(p['key_file'], secret=True), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise PublisherRefused('publisher_key_invalid')
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b'=')
    header = encode(evidence.encoded({'alg': 'RS256', 'typ': 'JWT'}))
    claims = encode(evidence.encoded({'iat': int(now) - 60, 'exp': int(now) + 540, 'iss': str(p['app_id'])}))
    unsigned = header + b'.' + claims
    signature = key.sign(unsigned, padding.PKCS1v15(), hashes.SHA256())
    return (unsigned + b'.' + encode(signature)).decode()


class AppTokens:
    """One mint per invocation, maximum three requests; no in-process refresh."""
    def __init__(self, raw, *, wire_fn=None, clock=time.time, audit=None):
        self.p = app_policy(raw)
        self.wire_fn = wire_fn or http_call
        self.clock = clock
        self.audit = audit or (lambda row: None)
        self.requests = 0
        self._token = None
        self._expires = 0
        self.outcome = 'not_requested'

    def status(self):
        return {'outcome': self.outcome, 'expires_at': self._expires or None,
                'requests': self.requests, 'max_requests': 3, 'valid': bool(self._token and self.clock() < self._expires - 60)}

    def get(self):
        now = self.clock()
        if self._token and now < self._expires - 60:
            return self._token
        self._token = None
        self._expires = 0
        self.outcome = 'refresh_failed'
        try:
            # Expiry ends this instance's lifetime budget. A fresh broker invocation
            # can mint a new token; this instance never silently resets its audit.
            if self.requests >= 3:
                raise PublisherRefused('publisher_token_unavailable')
            bearer = jwt(self.p, now=now)
            def call(endpoint, payload=None):
                if self.requests >= 3:
                    raise PublisherRefused('publisher_token_unavailable')
                self.requests += 1
                self.outcome = 'request_reserved'
                self.audit(self.status())  # durable budget/intent before network; no secret fields
                wire = self.wire_fn({'endpoint': endpoint, 'method': 'POST' if payload else 'GET',
                    'payload': payload, 'key': bearer, 'timeout': 5, 'max_response_bytes': 65536})
                if not isinstance(wire, dict) or wire.get('status') != 'ok':
                    raise PublisherRefused('publisher_token_unavailable')
                return json.loads(wire['body'], object_pairs_hook=evidence.unique_pairs)
            app = call('app')
            if app.get('id') != self.p['app_id'] or app.get('slug') + '[bot]' != self.p['login']:
                raise PublisherRefused('publisher_identity_unverified')
            installation = call('app/installations/' + str(self.p['installation_id']))
            permissions = {'issues': 'write', 'metadata': 'read'}
            if (installation.get('app_id') != self.p['app_id']
                    or installation.get('permissions') != permissions
                    or installation.get('suspended_at') is not None
                    or installation.get('account', {}).get('login') != self.p['repository'].split('/')[0]):
                raise PublisherRefused('publisher_token_scope_invalid')
            token = call('app/installations/' + str(self.p['installation_id']) + '/access_tokens',
                         {'repository_ids': [self.p['repository_id']], 'permissions': permissions})
            repositories = token.get('repositories')
            expires = evidence.timestamp(token.get('expires_at'))
            value = token.get('token')
            if (token.get('permissions') != permissions or not isinstance(repositories, list)
                    or len(repositories) != 1 or repositories[0].get('id') != self.p['repository_id']
                    or repositories[0].get('full_name') != self.p['repository']
                    or not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,4096}', value)
                    or not now + 60 < expires <= now + 3660):
                raise PublisherRefused('publisher_token_scope_invalid')
            self._token, self._expires = value, expires
            self.outcome = 'ready'
            self.audit(self.status())
            return value
        except Exception:
            self._token, self._expires = None, 0
            self.outcome = 'refresh_failed'
            try:
                self.audit(self.status())
            except Exception:
                pass  # Audit failure still refuses the operation; never leak its exception.
            raise PublisherRefused('publisher_token_unavailable') from None
