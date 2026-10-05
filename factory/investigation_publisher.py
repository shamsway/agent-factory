"""Opt-in dedicated GitHub publisher; no dispatcher integration or token fallback."""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

from . import config, incidents, investigation_model as model, investigation_evidence as evidence, investigation_outbox as outbox

KEY_NAME = "FACTORY_INVESTIGATION_PUBLISHER_TOKEN"


class PublisherRefused(ValueError):
    """Fixed codes only, never raw provider errors or credentials."""


def policy(raw):
    defaults = {"enabled": False, "allow_publish": False, "key": "", "login": "",
                "kind": "installation_token", "timeout": 30, "request_timeout": 5,
                "max_requests": 12, "max_response_bytes": 1048576}
    if not isinstance(raw, dict) or set(raw) - set(defaults):
        raise config.ConfigError("invalid investigation publisher policy")
    p = {**defaults, **raw}
    if (any(type(p[k]) is not bool for k in ("enabled", "allow_publish"))
            or not isinstance(p["key"], str) or len(p["key"]) > 4096
            or not re.fullmatch(r"[A-Za-z0-9_.-]*", p["key"])
            or not isinstance(p["login"], str)
            or (p["login"] and not re.fullmatch(r"[A-Za-z0-9_\[\]-]{1,100}", p["login"]))
            or not isinstance(p["kind"], str) or p["kind"] not in {"installation_token", "bot_token"}
            or any(type(p[k]) is not int or not 1 <= p[k] <= cap for k, cap in
                   (("timeout", 60), ("request_timeout", 10), ("max_requests", 12), ("max_response_bytes", 1048576)))
            or (p["enabled"] and not (p["allow_publish"] and p["key"] and p["login"]))):
        raise config.ConfigError("invalid investigation publisher policy")
    return p


def credential_status(cfg):
    p = policy(cfg.publisher)
    if not p["key"]:
        return "empty" if p["enabled"] else "not_configured"
    values = [*cfg.install["env"].values(), *cfg.apply_env.values(), cfg.llm_key,
              cfg.investigation.get("key")]
    return "invalid" if any(v and p["key"] == str(v) for v in values) or not p["login"] else "configured"


HTTP_CODE = '''import json,sys,urllib.request,urllib.error
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): return None
try:
 wire=json.loads(sys.stdin.buffer.read(65536))
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 req=urllib.request.Request('https://api.github.com/'+wire['endpoint'],
  data=json.dumps(wire['payload']).encode() if wire['payload'] is not None else None,
  headers={'Accept':'application/vnd.github+json','Content-Type':'application/json',
   'Authorization':'Bearer '+wire['key'],'X-GitHub-Api-Version':'2022-11-28',
   'User-Agent':'factory-investigation-publisher'},method=wire['method'])
 with opener.open(req,timeout=wire['timeout']) as response:
  raw=response.read(wire['max_response_bytes']+1)
 if len(raw)>wire['max_response_bytes']: print(json.dumps({'status':'unknown'}))
 else: print(json.dumps({'status':'ok','body':raw.decode('utf-8')}))
except urllib.error.HTTPError as error:
 # Timeouts/rate limits/5xx/redirects never authorize an automatic POST retry.
 definite=400 <= error.code < 500 and error.code not in (408,429)
 print(json.dumps({'status':'rejected' if definite else 'unknown','http':error.code if definite else 0}))
except Exception: print(json.dumps({'status':'unknown'}))
'''


def http_call(wire):
    child = subprocess.Popen([sys.executable, "-I", "-c", HTTP_CODE], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={},
                             close_fds=True, start_new_session=True)
    try:
        output, _ = child.communicate(evidence.encoded(wire), timeout=wire["timeout"])
        if child.returncode or len(output) > 6 * wire["max_response_bytes"] + 1024:
            return {"status": "unknown"}
        return json.loads(output, object_pairs_hook=evidence.unique_pairs)
    except Exception:
        return {"status": "unknown"}
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        child.stdin.close()
        child.stdout.close()


class Publisher:
    def __init__(self, cfg, *, wire_fn=None):
        self.p = policy(cfg.publisher)
        if credential_status(cfg) != "configured" or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", cfg.repo):
            raise PublisherRefused("publisher_credential_invalid")
        self.repo = cfg.repo
        self.deadline = time.monotonic() + self.p["timeout"]
        self.requests = 0
        self.wire_fn = wire_fn or http_call

    def api(self, endpoint, payload=None, method="GET"):
        comments = rf"repos/{re.escape(self.repo)}/issues/[1-9][0-9]*/comments"
        if method == "GET":
            allowed = endpoint in {"user", "installation/repositories?per_page=100"} or re.fullmatch(comments + r"\?per_page=100&page=(?:[1-9]|10)", endpoint)
            if payload is not None: allowed = False
        else:
            allowed = (method == "POST" and self.p["enabled"] and self.p["allow_publish"]
                       and re.fullmatch(comments, endpoint) and isinstance(payload, dict)
                       and set(payload) == {"body"} and isinstance(payload["body"], str)
                       and len(payload["body"].encode()) <= 16640
                       and re.match(r"<!-- factory-investigation-publication: [0-9a-f]{64} -->\n", payload["body"]))
        if not allowed:
            raise PublisherRefused("publisher_endpoint_refused")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.requests >= self.p["max_requests"]:
            raise PublisherRefused("publisher_budget")
        self.requests += 1
        wire = self.wire_fn({"endpoint": endpoint, "method": method, "payload": payload,
                            "key": self.p["key"], "timeout": min(self.p["request_timeout"], remaining),
                            "max_response_bytes": self.p["max_response_bytes"]})
        if not isinstance(wire, dict):
            raise PublisherRefused("publisher_outcome_unknown")
        if wire.get("status") == "rejected" and type(wire.get("http")) is int and 400 <= wire["http"] < 500 and wire["http"] not in (408,429):
            raise incidents.RequestRefused(wire["http"])
        if wire.get("status") != "ok" or not isinstance(wire.get("body"), str) or len(wire["body"].encode()) > self.p["max_response_bytes"]:
            raise PublisherRefused("publisher_outcome_unknown")
        try:
            return json.loads(wire["body"], object_pairs_hook=evidence.unique_pairs)
        except Exception:
            raise PublisherRefused("publisher_response_invalid") from None

    def verify(self):
        if self.p["kind"] == "bot_token":
            actor = self.api("user")
            valid = isinstance(actor, dict) and actor.get("login") == self.p["login"]
        else:
            rows = self.api("installation/repositories?per_page=100")
            valid = (isinstance(rows, dict) and isinstance(rows.get("repositories"), list)
                     and any(isinstance(r, dict) and r.get("full_name") == self.repo for r in rows["repositories"]))
        if not valid:
            raise PublisherRefused("publisher_identity_unverified")
        # App repository access does not prove bot login or Issues-write scope.
        # POST author is checked by the outbox; live write acceptance is separate.
        return True


def verify_status(cfg, *, wire_fn=None):
    status = credential_status(cfg)
    if status != "configured": return status
    try:
        Publisher(cfg, wire_fn=wire_fn).verify()
        return "read_verified"
    except incidents.RequestRefused:
        return "invalid"
    except Exception:
        return "unavailable"


def send(cfg, incident, run, *, wire_fn=None, now=None):
    p = policy(cfg.publisher)
    if not (p["enabled"] and p["allow_publish"]):
        raise PublisherRefused("publisher_disabled")
    client = Publisher(cfg, wire_fn=wire_fn)
    client.verify()
    return outbox.deliver(cfg, incident, run, publisher=client, publisher_login=p["login"], now=now)


def main(argv):
    parser = argparse.ArgumentParser(prog="factory investigation-publish")
    parser.add_argument("--incident", required=True)
    parser.add_argument("--run", required=True)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--preview", action="store_true")
    action.add_argument("--enqueue", action="store_true")
    action.add_argument("--send", action="store_true")
    parser.add_argument("--confirm-public-write", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.send and not args.confirm_public_write:
            raise PublisherRefused("public_write_confirmation_required")
        cfg = config.load()
        if args.preview:
            envelope = model.prepare(cfg, args.incident, args.run)
            print(json.dumps({"repository": envelope.repository, "issue": envelope.issue,
                              "key": envelope.idempotency_key, "body": envelope.body, "public_write": False}))
            return 0
        if args.enqueue:
            row = outbox.enqueue(cfg, args.incident, args.run)
        elif args.send:
            row = send(cfg, args.incident, args.run)
        else:
            print(json.dumps(outbox.snapshot(cfg)))
            return 0
        print(json.dumps({"state": row["state"], "code": row["code"]}))
        return 0 if row["state"] in {"queued", "delivered"} else 1
    except PublisherRefused as error:
        allowed = {"publisher_disabled", "publisher_credential_invalid", "publisher_endpoint_refused",
                   "publisher_budget", "publisher_outcome_unknown", "publisher_response_invalid",
                   "publisher_identity_unverified", "public_write_confirmation_required"}
        code = str(error) if str(error) in allowed else "publisher_unavailable"
        print(json.dumps({"ok": False, "code": code}))
        return 1
    except incidents.RequestRefused:
        print(json.dumps({"ok": False, "code": "publisher_auth_rejected"}))
        return 1
    except (evidence.EvidenceRefused, config.ConfigError, OSError, ValueError):
        print(json.dumps({"ok": False, "code": "publisher_unavailable"}))
        return 1
