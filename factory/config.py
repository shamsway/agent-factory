"""Per-repository configuration: `.factory.toml` at the target repo root.

Everything the factory scripts used to hardcode for one repo lives here:
the GitHub slug, the optional upstream remote, worker/reviewer commands,
and the gate's check list. Labels and branch naming (`agent/<n>`) are
conventions, not configuration.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from factory import lifecycle

CONFIG_NAME = ".factory.toml"
LESSONS_NAME = ".factory-lessons.md"  # committed; `factory learn` writes, every worker prompt reads

# Triage roles -> label strings. Fixed by convention; `factory init` creates them.
LABEL_VIABILITY = "needs-viability"
LABEL_REVIEW = "needs-review"
LABEL_TRIAGE = "needs-triage"
LABEL_INFO = "needs-info"
LABEL_AGENT = "ready-for-agent"
LABEL_INVESTIGATE = "ready-for-investigation"
LABEL_HUMAN = "ready-for-human"
LABEL_APPROVED = "factory-approved"
LABEL_CHORE = "chore"
# Reporter/detector-applied marker, never a triage decision itself: exempts an
# issue from the acceptance-criteria lint so "service is down, cause unknown"
# incident reports aren't wrongly bounced to needs-info.
LABEL_OPS = "kind/ops"
LABEL_INITIATIVE = "initiative"
LABEL_WONTFIX = "wontfix-proposal"
LABELS = {
    LABEL_VIABILITY: ("D4C5F9", "Opt in to a manager build/defer recommendation before triage"),
    LABEL_REVIEW: ("D4C5F9", "Opt in to a manager PR direction recommendation before review"),
    LABEL_TRIAGE: ("FBCA04", "Maintainer needs to evaluate this issue"),
    LABEL_INFO: ("D4C5F9", "Waiting on reporter for more information"),
    LABEL_AGENT: ("0E8A16", "Fully specified and ready for an AFK agent"),
    LABEL_INVESTIGATE: ("1D76DB", "Evidence-gathering pass; agent reports, does not diff"),
    LABEL_HUMAN: ("B60205", "Requires human implementation"),
    LABEL_APPROVED: ("0E8A16", "Reviewer APPROVE recorded by the factory; merge-stage precondition"),
    LABEL_CHORE: ("C2E0C6", "Mechanical task; routed to the chore worker"),
    LABEL_OPS: ("5319E7", "Operational/infra issue; exempt from the acceptance-criteria triage lint"),
    LABEL_WONTFIX: ("EDEDED", "Triage or manager proposes not to action this; a human decides"),
    LABEL_INITIATIVE: ("1D76DB", "Shared initiative plan read by `factory plan`; never triaged, dispatched, managed or merged"),
}

DEFAULT_LEAK_PATTERN = (
    r"internal|confidential|proprietary|private|jira|confluence|\.corp|\.internal"
    r"|AKIA[0-9A-Z]{16}|-----BEGIN[ A-Z]*PRIVATE KEY-----"
)
DEFAULT_WORKER = ["omp", "-p", "--cwd", "{cwd}", "@{prompt}"]
DEFAULT_CHORE_WORKER = ["droid", "exec", "-f", "{prompt}", "--auto", "medium", "--cwd", "{cwd}"]
DEFAULT_REVIEWER = ["omp", "-p", "--no-session", "--model", "anthropic/claude-fable-5-1", "{prompt}"]
DEFAULT_LLM_URL = "http://127.0.0.1:11434/v1/chat/completions"
DEFAULT_LLM_MODEL = "qwen3:30b"
DEFAULT_INSTALL = {"every": "10min", "dashboard": False, "host": "127.0.0.1", "python": None, "env": {}}
# The dashboard's /api/act performs real GitHub mutations with the operator's
# own `gh` credentials and has no authentication of its own -- policy is
# loopback-only + SSH tunnel access, enforced by a hard refusal to bind
# elsewhere (see dashboard.py's main()). Escape hatch for someone who
# deliberately wants LAN/WAN exposure (and puts real auth in front of it,
# e.g. a reverse proxy): set FACTORY_DASHBOARD_ALLOW_REMOTE=1 in
# `[install].env` (host config) -- same mechanism used to reach any other
# systemd-unit env var, see onboard.py's `units()`.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
DASHBOARD_ALLOW_REMOTE_VAR = "FACTORY_DASHBOARD_ALLOW_REMOTE"

# Host-side layer: `$XDG_CONFIG_HOME/factory/config.toml`, same table shapes
# as `.factory.toml`. `[defaults.*]` < `[repo."owner/name".*]` < the repo file.
# Only these tables/keys are taken from the host: a clone on another machine
# must run the same gate, so gate checks, leak scan and upstream never come
# from here. Everything else in the host file is left for other tools (District).
# `worker_wrap` is host-only: a committed `[worker_wrap]` is refused, never merged.
HOST_TABLES = frozenset({"triage", "workers", "worker_wrap", "review", "manager", "install", "investigation"})
# `apply.env` is credential-shaped like `install.env` -- host-owned so it
# never lives in the committed repo file -- but `apply.enabled`/`apply.dir`
# are policy about this repo (does merging it trigger terraform apply, and
# where) and stay repo-owned, same split already used for `dashboard`.
HOST_KEYS = {"dashboard": ("port",), "gate": ("lock",), "apply": ("env",)}

# Every key the loader reads, by table; `factory doctor` reports anything else.
# `workers` is label-keyed, `gate.check` is a list of {name, run, exclusive}.
KNOWN_KEYS = {
    "repo": ("slug", "upstream", "main"),
    "dispatch": ("max_active", "max_attempts", "budget_min", "review_rounds", "cost_pattern", "signoff"),
    "workers": None,
    "worker_wrap": ("command",),
    "review": ("command",),
    "manager": ("model", "command", "rounds", "review", "stale_days", "max_active_cap", "budget_min_cap"),
    "gate": ("timeout", "lock", "check"),
    "leak_scan": ("pattern", "exclude"),
    "triage": ("url", "model", "key"),
    "investigation": ("enabled", "allow_export", "url", "model", "key", "allow_loopback_http",
                      "max_input_bytes", "max_output_tokens", "token_budget", "timeout", "max_requests", "send_store_false", "allow_shared_model_key"),
    "journal": ("max_mb", "retention"),
    "dashboard": ("port", "theme"),
    "install": ("every", "dashboard", "host", "python", "env"),
    "apply": ("enabled", "dir", "env", "targets", "baseline", "supersession", "adapter", "verify", "diagnostics"),
    "collaboration": ("fallback", "reasons", "components"),
}
CHECK_KEYS = ("name", "run", "exclusive", "timeout")
VERIFY_KEYS = ("nomad", "nomad_addr", "timeout", "interval", "periodic", "check")
VERIFY_CHECK_KEYS = ("name", "run", "timeout")
PERIODIC_POLICIES = ("registered", "launch")
ROUTE_REASONS = ("requirements", "implementation", "ci", "unknown")
# GitHub login, or `@org/team`. Syntax only: never proof of membership or authorization.
OWNER = re.compile(r"@?(?P<login>[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)|(?P<team>@[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100})")


class ConfigError(SystemExit):
    def __init__(self, msg: str) -> None:
        super().__init__(f"factory: {msg}")


@dataclass
class DeployTarget:
    """One deployment target (e.g. Terraform root, Nomad cluster, etc.)."""

    name: str
    dir: str
    enabled: bool = True
    backend_key: str = ""
    adapter: str = "terraform"
    verify: VerifyPolicy | None = None
    diagnostics: dict | None = None


@dataclass
class VerifyPolicy:
    """Post-apply health verification for one target (see factory/health.py).

    Off unless the target's `verify` table asks for something to observe.
    """

    nomad: bool = False  # observe the nomad_job resources the applied plan changed
    nomad_addr: str = ""  # falls back to NOMAD_ADDR in the apply env
    timeout: int = 300  # seconds for the whole observation window
    interval: int = 5  # seconds between polls
    periodic: str = "registered"  # or "launch": force one run and require it to complete
    checks: list[Check] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return self.nomad or bool(self.checks)


def _positive_int(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(f"{where} must be a positive integer")
    return value


def verify_policy(raw: object, where: str) -> VerifyPolicy | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be a table")
    unknown = sorted(k for k in raw if k not in VERIFY_KEYS)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)}")
    policy = VerifyPolicy()
    if "nomad" in raw:
        if not isinstance(raw["nomad"], bool):
            raise ConfigError(f"{where}.nomad must be true or false")
        policy.nomad = raw["nomad"]
    if "nomad_addr" in raw:
        if not isinstance(raw["nomad_addr"], str):
            raise ConfigError(f"{where}.nomad_addr must be a string")
        policy.nomad_addr = raw["nomad_addr"]
    for key in ("timeout", "interval"):
        if key in raw:
            setattr(policy, key, _positive_int(raw[key], f"{where}.{key}"))
    if policy.interval > policy.timeout:
        raise ConfigError(f"{where}.interval must not exceed {where}.timeout")
    if "periodic" in raw:
        if raw["periodic"] not in PERIODIC_POLICIES:
            raise ConfigError(f"{where}.periodic must be one of {', '.join(PERIODIC_POLICIES)}")
        policy.periodic = raw["periodic"]
    for i, c in enumerate(raw.get("check") or []):
        at = f"{where}.check[{i}]"
        if not isinstance(c, dict) or not isinstance(c.get("name"), str) or not c["name"]:
            raise ConfigError(f"{at} needs a name")
        if [k for k in c if k not in VERIFY_CHECK_KEYS]:
            raise ConfigError(f"{at}: allowed keys are {', '.join(VERIFY_CHECK_KEYS)}")
        run = c.get("run")
        if not isinstance(run, list) or not run or not all(isinstance(a, str) for a in run):
            raise ConfigError(f"{at}.run must be a non-empty list of strings")
        timeout = _positive_int(c["timeout"], f"{at}.timeout") if "timeout" in c else None
        policy.checks.append(Check(c["name"], list(run), timeout=timeout))
    names = [c.name for c in policy.checks]
    if len(set(names)) != len(names):
        raise ConfigError(f"{where}.check names must be unique")
    return policy


@dataclass
class Check:
    """One gate check: argv run inside the worktree; nonzero exit = FAIL.

    `exclusive` checks hold the host lock (shared GPU, licence server, ...)
    so two worktrees never run them at once. `timeout` overrides the gate's
    global per-check timeout for this one check (e.g. a live-system health
    probe wants seconds, a Terraform plan wants minutes).
    """

    name: str
    run: list[str]
    exclusive: bool = False
    timeout: int | None = None


@dataclass
class Config:
    root: Path  # main checkout of the target repository (never a worktree)
    repo: str  # GitHub "owner/name"
    upstream: str | None = None  # remote whose main syncs into ours; None disables
    main: str = "main"
    max_active: int = 2
    max_attempts: int = 3
    budget_min: int = 90
    review_rounds: int = 1  # REVISE -> worker -> re-review cycles before escalating
    signoff: bool = True  # `git commit -s`; Signed-off-by trailer on merges
    cost_pattern: str | None = None  # regex with one capture: dollars in the worker log
    workers: dict[str, list[str]] = field(
        default_factory=lambda: {"default": DEFAULT_WORKER, LABEL_CHORE: DEFAULT_CHORE_WORKER}
    )
    worker_when: dict[str, str] = field(default_factory=dict)
    # Host-only argv prefix for every worker launch: a trusted operator executable, not a sandbox.
    worker_wrap: list[str] = field(default_factory=list)
    reviewer: list[str] = field(default_factory=lambda: list(DEFAULT_REVIEWER))
    manager: list[str] | None = None
    manager_rounds: int = 1
    manager_review: str = "escalated"
    manager_stale_days: int = 7
    # Ceilings for the fleet manager (`district manage`) raising `max_active`/`budget_min`; None = no cap.
    manager_max_active_cap: int | None = None
    manager_budget_min_cap: int | None = None
    checks: list[Check] = field(default_factory=list)
    check_timeout: int = 1200
    lock: Path = Path("/tmp/factory.lock")  # host-wide: one GPU, many repos
    leak_pattern: str | None = DEFAULT_LEAK_PATTERN
    leak_exclude: list[str] = field(default_factory=list)
    llm_url: str = DEFAULT_LLM_URL
    llm_model: str = DEFAULT_LLM_MODEL
    llm_key: str = ""  # bearer token for a gated endpoint (e.g. LiteLLM); host config only, never committed
    investigation: dict = field(default_factory=dict, repr=False)  # host-only model role
    manager_model: str | None = None  # dashboard's no-tools OMP briefing; never a command
    dashboard_port: int = 8765
    dashboard_theme: Path | None = None  # CSS file served after the built-in stylesheet
    journal_max_mb: int = 64  # events.jsonl rotates into events.jsonl.N.gz past this size
    journal_retention: int = 8  # gzip segments kept; older closed-execution lifecycle rows are dropped
    install: dict = field(default_factory=lambda: dict(DEFAULT_INSTALL))  # `factory install` defaults
    # `[collaboration]`: human decision owners for `factory plan route`; None = section absent (legacy behaviour).
    collaboration: dict | None = None
    apply_enabled: bool = False  # this repo's merges require a human review approval and are apply-eligible
    apply_dir: str = "."  # terraform root, relative to repo root, that `factory apply` plans/applies
    apply_env: dict = field(default_factory=dict)  # env for `factory apply` only; never the dispatcher's
    targets: dict[str, DeployTarget] = field(default_factory=dict)  # deployment targets, keyed by name
    apply_baseline: str | None = None  # commit SHA or PR number prior to which deployments are ignored
    apply_supersession: str = "sequential"  # "sequential" (strict commit order) or "none"
    raw_repo: dict = field(default_factory=dict)  # the committed file alone, before host layering

    @property
    def name(self) -> str:
        return self.repo.rsplit("/", 1)[-1]

    @property
    def factory(self) -> Path:
        """On-disk state: worktrees, locks, logs, prompts. Gitignored."""
        return self.root / ".factory"

    @property
    def unit(self) -> str:
        """systemd user-unit stem: `<unit>.timer`, `<unit>.service`, `<unit>-dashboard.service`."""
        return f"factory-{self.name}"

    def worker(self, labels: set[str], prompt: Path, cwd: Path) -> list[str]:
        """argv for the worker that owns these ticket labels (first match wins)."""
        argv = next((self.workers[k] for k in self.workers if k in labels), self.workers["default"])
        return expand([*self.worker_wrap, *argv], prompt=str(prompt), cwd=str(cwd),
                      root=str(self.root), repo=self.repo, home=str(Path.home()))

    def review_cmd(self, prompt: str) -> list[str]:
        return expand(self.reviewer, prompt=prompt)

    def manager_cmd(self, prompt_path: Path, cwd: Path) -> list[str]:
        """Expand the manager's prompt file, matching the worker transport."""
        argv = self.manager or []
        if argv and Path(argv[0]).name == "omp" and "{prompt}" in argv:
            raise ConfigError('manager.command: use "@{prompt}" instead of bare "{prompt}" for omp')
        return expand(argv, prompt=str(prompt_path), cwd=str(cwd))


def expand(argv: list[str], **values: str) -> list[str]:
    """Substitute `{name}` placeholders; literal braces elsewhere are left alone."""
    out = []
    for arg in argv:
        for key, val in values.items():
            arg = arg.replace("{" + key + "}", val)
        out.append(arg)
    return out


def git(root: Path | None, *args: str) -> str:
    cmd = ["git", *(("-C", str(root)) if root else ()), *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise ConfigError(f"`{' '.join(cmd)}` failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def repo_root(start: Path | None = None) -> Path:
    """Main checkout root, even when called from inside one of its worktrees."""
    common = git(start, "rev-parse", "--path-format=absolute", "--git-common-dir")
    return Path(common).parent


def remote_slug(root: Path, remote: str) -> str:
    url = git(root, "remote", "get-url", remote)
    if "github.com" not in url:
        raise ConfigError(f"remote `{remote}` ({url}) is not on github.com; set [repo].slug")
    return url.rsplit("github.com", 1)[-1].strip(":/").removesuffix(".git")


def host_config_path() -> Path:
    """The one resolver host-config readers, writers, doctor and verification all
    use. Prefers `factory/config.toml`; falls back to the pre-rename
    `agent-factory/config.toml` only while the new path is genuinely absent --
    a dangling preferred symlink is a configuration error, not a fallback, so
    existence of the symlink itself (not its target) decides preference."""
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    new_path = Path(base) / "factory" / "config.toml"
    old_path = Path(base) / "agent-factory" / "config.toml"
    if new_path.exists() or new_path.is_symlink():
        return new_path
    if old_path.exists() or old_path.is_symlink():
        return old_path
    return new_path


def host_config() -> dict:
    path = host_config_path()
    if path.is_symlink() and not path.exists():
        raise ConfigError(f"{path}: dangling symlink")
    if not path.exists():
        return {}
    try:
        text = path.read_text()
    except OSError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc


def host_filter(table: dict) -> dict:
    """Keep only the host-owned tables/keys of one host section."""
    out = {k: table[k] for k in HOST_TABLES if isinstance(table.get(k), dict)}
    for name, keys in HOST_KEYS.items():
        sub = table.get(name)
        if isinstance(sub, dict) and (kept := {k: sub[k] for k in keys if k in sub}):
            out[name] = kept
    return out


def merge(base: dict, over: dict) -> dict:
    """Recursive on dicts; scalars and lists in `over` replace."""
    out = dict(base)
    for k, v in over.items():
        out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def unknown_keys(raw: dict) -> list[str]:
    """Dotted paths in a `.factory.toml`-shaped dict the loader does not read."""
    out = []
    for table, val in raw.items():
        if table not in KNOWN_KEYS:
            out.append(table)
            continue
        known = KNOWN_KEYS[table]
        if known is None or not isinstance(val, dict):
            continue
        out += [f"{table}.{k}" for k in val if k not in known]
        if table == "gate":
            for i, c in enumerate(val.get("check", [])):
                out += [f"gate.check[{i}].{k}" for k in c if k not in CHECK_KEYS]
    return out


def owner(value: object, where: str) -> str:
    """Normalize one configured owner: `login` or `@org/team`; syntactic invalidity is a ConfigError."""
    match = OWNER.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise ConfigError(f"{where}: expected a GitHub login or @org/team, got {value!r}")
    return match["login"] or match["team"]


def collaboration_settings(table: object) -> dict:
    """Validate `[collaboration]`: fallback owner, per-reason owners, exact path-prefix component owners."""
    if not isinstance(table, dict):
        raise ConfigError("[collaboration] must be a table")
    out = {"fallback": None, "reasons": {}, "components": {}}
    if "fallback" in table:
        out["fallback"] = owner(table["fallback"], "collaboration.fallback")
    reasons, components = table.get("reasons", {}), table.get("components", {})
    if not isinstance(reasons, dict) or not isinstance(components, dict):
        raise ConfigError("collaboration.reasons and collaboration.components must be tables")
    for reason, value in reasons.items():
        if reason not in ROUTE_REASONS[:-1]:
            raise ConfigError(f"collaboration.reasons.{reason}: expected one of {', '.join(ROUTE_REASONS[:-1])}")
        out["reasons"][reason] = owner(value, f"collaboration.reasons.{reason}")
    for prefix, value in components.items():
        parts = prefix.strip("/").split("/")
        if not prefix or prefix.startswith("/") or "\\" in prefix or any(p in ("", ".", "..") for p in parts):
            raise ConfigError(f"collaboration.components: {prefix!r} is not a repo-relative path prefix")
        normalized = "/".join(parts)
        if normalized in out["components"]:
            raise ConfigError(f"collaboration.components: duplicate normalized prefix {normalized!r}")
        out["components"][normalized] = owner(value, f"collaboration.components.{prefix!r}")
    return out


def manager_settings(table: dict) -> tuple[list[str] | None, str | None]:
    """Normalize manager argv and select the read-only briefing model; never execute."""
    if not isinstance(table, dict):
        raise ConfigError("[manager] must be a table")
    model = table.get("model")
    command = None
    if "command" in table:
        command = table["command"]
        if isinstance(command, str):
            try:
                command = shlex.split(command)
            except ValueError as exc:
                raise ConfigError(f"manager.command: {exc}") from exc
        if not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
            raise ConfigError("manager.command must be an argv array or command string")
    if model is None and command:
        for i, arg in enumerate(command):
            if arg == "--model":
                if i + 1 == len(command):
                    raise ConfigError("manager.command: --model needs a value")
                model = command[i + 1]
            elif arg.startswith("--model="):
                model = arg.split("=", 1)[1]
    if model is not None and (
        not isinstance(model, str) or not model or len(model) > 200
        or model.startswith("-") or any(c.isspace() or ord(c) < 32 for c in model)
    ):
        raise ConfigError("manager.model must be a nonempty model selector (≤ 200 chars, no whitespace)")
    return command, model


def load(start: Path | None = None) -> Config:
    """Load `<root>/.factory.toml` over the host layer; every key optional except a resolvable repo slug."""
    root = repo_root(start)
    path = root / CONFIG_NAME
    raw: dict = {}
    if path.exists():
        try:
            raw = tomllib.loads(path.read_text())
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: {exc}") from exc
    slug = raw.get("repo", {}).get("slug") or remote_slug(root, "origin")
    host = host_config()
    for section in (host.get("defaults", {}), host.get("repo", {}).get(slug, {})):
        if "investigation" in section and not isinstance(section["investigation"], dict):
            raise ConfigError("host investigation must be a table")
        if "worker_wrap" in section and not isinstance(section["worker_wrap"], dict):
            raise ConfigError(f"{host_config_path()}: worker_wrap must be a table")
    layered = merge(host_filter(host.get("defaults", {})), host_filter(host.get("repo", {}).get(slug, {})))
    raw, raw_repo = merge(layered, raw), raw
    repo_t, dispatch, workers = raw.get("repo", {}), raw.get("dispatch", {}), raw.get("workers", {})
    gate, leak, triage, dash = raw.get("gate", {}), raw.get("leak_scan", {}), raw.get("triage", {}), raw.get("dashboard", {})
    manager = raw.get("manager", {})
    if "investigation" in raw_repo:
        raise ConfigError("[investigation] is host-only")
    cfg = Config(root=root, repo=slug, raw_repo=raw_repo)
    from .investigation_model import policy
    cfg.investigation = policy(raw.get("investigation", {}))
    cfg.upstream = repo_t.get("upstream") or None
    cfg.main = repo_t.get("main", cfg.main)
    cfg.max_active = int(dispatch.get("max_active", cfg.max_active))
    cfg.max_attempts = int(dispatch.get("max_attempts", cfg.max_attempts))
    cfg.budget_min = int(dispatch.get("budget_min", cfg.budget_min))
    cfg.review_rounds = int(dispatch.get("review_rounds", cfg.review_rounds))
    cfg.cost_pattern = dispatch.get("cost_pattern") or None
    cfg.signoff = bool(dispatch.get("signoff", cfg.signoff))
    if workers:
        if "default" not in workers:
            raise ConfigError(f"{path}: [workers] needs a `default` command")
        cfg.workers = {}
        for label, entry in workers.items():
            command = entry.get("command") if isinstance(entry, dict) else entry
            when = entry.get("when", "") if isinstance(entry, dict) else ""
            if not isinstance(command, list) or not command or any(not isinstance(arg, str) for arg in command) or not command[0]:
                raise ConfigError(f"{path}: workers.{label} needs a non-empty command argv")
            if not isinstance(when, str):
                raise ConfigError(f"{path}: workers.{label}.when must be text")
            cfg.workers[label] = command
            if when:
                cfg.worker_when[label] = when
    if "worker_wrap" in raw_repo:
        raise ConfigError(f"{path}: [worker_wrap] is host-only; set it in {host_config_path()} "
                          "[defaults.worker_wrap] or [repo.\"<slug>\".worker_wrap]")
    wrap = raw.get("worker_wrap", {})
    if "command" in wrap:
        command = wrap["command"]
        if not isinstance(command, list) or not command or any(not isinstance(a, str) for a in command) or not command[0]:
            raise ConfigError("worker_wrap.command needs a non-empty argv array of strings")
        cfg.worker_wrap = command
    if "command" in raw.get("review", {}):
        cfg.reviewer = list(raw["review"]["command"])
    cfg.manager, cfg.manager_model = manager_settings(manager)
    cfg.manager_rounds = int(manager.get("rounds", cfg.manager_rounds))
    cfg.manager_review = manager.get("review", cfg.manager_review)
    if cfg.manager_review not in ("escalated", "all"):
        raise ConfigError("manager.review must be escalated or all")
    cfg.manager_stale_days = manager.get("stale_days", cfg.manager_stale_days)
    if type(cfg.manager_stale_days) is not int or cfg.manager_stale_days <= 0:
        raise ConfigError("manager.stale_days must be a positive integer")
    for key in ("max_active_cap", "budget_min_cap"):
        cap = manager.get(key)
        if cap is not None and (isinstance(cap, bool) or not isinstance(cap, int) or cap < 1):
            raise ConfigError(f"manager.{key} must be a positive integer")
        setattr(cfg, f"manager_{key}", cap)
    journal = raw.get("journal", {})
    for key in ("max_mb", "retention"):
        value = journal.get(key, getattr(cfg, f"journal_{key}"))
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ConfigError(f"journal.{key} must be a positive integer")
        setattr(cfg, f"journal_{key}", value)
    if "collaboration" in raw:
        cfg.collaboration = collaboration_settings(raw["collaboration"])
    cfg.check_timeout = int(gate.get("timeout", cfg.check_timeout))
    cfg.lock = Path(gate.get("lock", cfg.lock))
    cfg.checks = [
        Check(c["name"], list(c["run"]), bool(c.get("exclusive", False)), c.get("timeout"))
        for c in gate.get("check", [])
    ]
    names = [c.name for c in cfg.checks]
    if len(set(names)) != len(names) or {"conflict-markers", "leak-scan"} & set(names):
        raise ConfigError(f"{path}: gate check names must be unique and not conflict-markers/leak-scan")
    if "pattern" in leak:
        cfg.leak_pattern = leak["pattern"] or None
    cfg.leak_exclude = list(leak.get("exclude", []))
    cfg.llm_url = triage.get("url", cfg.llm_url)
    cfg.llm_model = triage.get("model", cfg.llm_model)
    cfg.llm_key = str(triage.get("key", cfg.llm_key))
    cfg.dashboard_port = int(dash.get("port", cfg.dashboard_port))
    cfg.dashboard_theme = root / dash["theme"] if dash.get("theme") else None
    cfg.install = merge(DEFAULT_INSTALL, raw.get("install", {}))
    python = cfg.install["python"]
    if python is not None and (not isinstance(python, str) or not python):
        raise ConfigError("[install].python must be a non-empty path")
    cfg.install["dashboard"] = bool(cfg.install["dashboard"])
    cfg.install["env"] = {k: str(v) for k, v in cfg.install["env"].items()}
    lifecycle.MAX_BYTES = cfg.journal_max_mb * 1024 * 1024
    lifecycle.RETENTION = cfg.journal_retention
    apply_t = raw.get("apply", {})
    cfg.apply_enabled = bool(apply_t.get("enabled", cfg.apply_enabled))
    cfg.apply_dir = apply_t.get("dir", cfg.apply_dir)
    cfg.apply_env = {k: str(v) for k, v in apply_t.get("env", {}).items()}
    cfg.apply_baseline = str(apply_t["baseline"]) if "baseline" in apply_t else None
    cfg.apply_supersession = str(apply_t.get("supersession", cfg.apply_supersession))

    raw_targets = apply_t.get("targets")
    default_adapter = str(apply_t.get("adapter", "terraform"))
    targets: dict[str, DeployTarget] = {}
    if isinstance(raw_targets, list):
        for item in raw_targets:
            if isinstance(item, dict) and "name" in item:
                name = str(item["name"])
                targets[name] = DeployTarget(
                    name=name,
                    dir=str(item.get("dir", cfg.apply_dir)),
                    enabled=bool(item.get("enabled", True)),
                    backend_key=str(item.get("backend_key", "")),
                    adapter=str(item.get("adapter", default_adapter)),
                    verify=verify_policy(item.get("verify"), f"apply.targets.{name}.verify"),
                    diagnostics=item.get("diagnostics"),
                )
    elif isinstance(raw_targets, dict):
        for name, item in raw_targets.items():
            if isinstance(item, dict):
                targets[name] = DeployTarget(
                    name=name,
                    dir=str(item.get("dir", cfg.apply_dir)),
                    enabled=bool(item.get("enabled", True)),
                    backend_key=str(item.get("backend_key", "")),
                    adapter=str(item.get("adapter", default_adapter)),
                    verify=verify_policy(item.get("verify"), f"apply.targets.{name}.verify"),
                    diagnostics=item.get("diagnostics"),
                )
    if targets and "verify" in apply_t:
        raise ConfigError("[apply].verify applies to the implicit default target only; "
                          "with [apply.targets], set verify on each target")
    if targets and "diagnostics" in apply_t:
        raise ConfigError("with [apply.targets], set diagnostics on each target")
    if not targets:
        targets["default"] = DeployTarget(
            name="default",
            dir=cfg.apply_dir,
            enabled=cfg.apply_enabled,
            adapter=default_adapter,
            verify=verify_policy(apply_t.get("verify"), "apply.verify"),
            diagnostics=apply_t.get("diagnostics"),
        )
    from factory.diagnostics import policy as diagnostic_policy
    for target in targets.values():
        diagnostic_policy(target.diagnostics)
    cfg.targets = targets
    return cfg
