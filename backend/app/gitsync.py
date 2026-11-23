"""Optional sync of the JSON config history of L3 rules with a git repository (PLAN 4a).

App -> git: every config commit becomes a git commit with the same author, date and message, on
`usecases/<L1>/<L2>/<L3>.json`. Configurations used to be YAML in `<L3>.yaml`; the first export
of a rule after that change moves the file to `.json`. Configurations of L2 use cases (no longer
used, issue #25) are not exported any more; what is in git already stays there. Config tags
become git tags named `<code>/<tag>`. Each exported commit carries a `Magma-Commit: <sha>`
trailer, so a sync never exports a commit twice, even after a failed push. The local working
copy is only a cache: it is reset to the remote branch before each sync and unpushed commits
are simply exported again.

Git -> app (two-way sync, `GIT_PULL=true`): commits pushed to the branch by people (no trailer)
that change a config file become new config commits in the app, with the git author, date and
message. Each one keeps its git commit id, so it is never exported back. When the same config
was also changed in the app and that change is not in git yet, the app version wins and is pushed
on top; the git change stays in the repository history and is listed in the import notes.
"""

import base64
import logging
import os
import re
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app import audit, configs
from app.config import Settings
from app.db import try_job_lock
from app.models import ConfigCommit, ConfigTag, GitSyncState, L2UseCase, L3UseCase

log = logging.getLogger(__name__)

TRAILER = "Magma-Commit"
OUR_TAG = re.compile(r"^[A-Z0-9]{2}-[A-Z0-9]{3}(-[0-9A-Z]+)?/")


class GitError(RuntimeError):
    pass


def redact(url: str) -> str:
    """Hide a password or token that someone put into the URL itself."""
    return re.sub(r"//[^/@]*@", "//***@", url)


@dataclass
class Result:
    exported: int = 0
    imported: int = 0
    tags: int = 0
    head: str | None = None
    notes: list[str] = field(default_factory=list)


class Repo:
    def __init__(self, settings: Settings):
        self.s = settings
        self.dir = Path(settings.git_workdir)

    def _env(self) -> dict[str, str]:
        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_COMMITTER_NAME": "MaGMa UCF",
            "GIT_COMMITTER_EMAIL": f"magma@{self.s.git_author_email_domain}",
        }
        if self.s.git_ssh_key_file:
            known = self.dir.parent / "git_known_hosts"
            env["GIT_SSH_COMMAND"] = (
                f"ssh -i {self.s.git_ssh_key_file} -o IdentitiesOnly=yes "
                f"-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile={known}"
            )
        return env

    def _auth(self) -> list[str]:
        if not self.s.git_token:
            return []
        cred = base64.b64encode(f"{self.s.git_username}:{self.s.git_token}".encode()).decode()
        # passed per call, never written to .git/config
        return ["-c", f"http.extraHeader=Authorization: Basic {cred}"]

    def git(
        self, *args: str, env: dict | None = None, remote: bool = False, check=True, raw=False
    ) -> str:
        cmd = ["git", *(self._auth() if remote else []), *args]
        p = subprocess.run(
            cmd,
            cwd=self.dir,
            env={**self._env(), **(env or {})},
            capture_output=True,
            text=True,
            timeout=120,
        )
        if check and p.returncode != 0:
            msg = (p.stderr or p.stdout).strip().replace(self.s.git_token or "\0", "***")
            raise GitError(f"git {args[0]}: {redact(msg)}")
        return p.stdout if raw else p.stdout.strip()

    def ok(self, *args: str, remote: bool = False) -> bool:
        return (
            subprocess.run(
                ["git", *(self._auth() if remote else []), *args],
                cwd=self.dir,
                env=self._env(),
                capture_output=True,
                timeout=120,
            ).returncode
            == 0
        )

    def prepare(self) -> None:
        """Create the working copy on first use and bring it up to date with the remote."""
        self.dir.mkdir(parents=True, exist_ok=True)
        b = self.s.git_branch
        if not (self.dir / ".git").is_dir():
            self.git("init", "-q", "-b", b)
            self.git("remote", "add", "origin", self.s.git_remote_url)
        else:
            self.git("remote", "set-url", "origin", self.s.git_remote_url)
        self.git("config", "user.name", "MaGMa UCF")
        self.git("config", "user.email", f"magma@{self.s.git_author_email_domain}")
        self.git("fetch", "-q", "--prune", "--prune-tags", "--force", "origin", remote=True)
        # The database is the source of truth and the working copy only a cache: start from the
        # remote branch; commits that were not pushed yet are exported again by sync().
        if self.remote_head():
            self.git("checkout", "-q", "-f", "-B", b, f"origin/{b}")
            self.git("clean", "-q", "-fd")

    def remote_head(self) -> str | None:
        ref = f"refs/remotes/origin/{self.s.git_branch}"
        if not self.ok("rev-parse", "-q", "--verify", ref):
            return None
        return self.git("rev-parse", ref)

    def exported(self) -> dict[str, str]:
        """Magma commit sha -> git commit sha for everything reachable from HEAD."""
        if not self.ok("rev-parse", "-q", "--verify", "HEAD"):
            return {}
        out = self.git("log", f"--format=%H %(trailers:key={TRAILER},valueonly,separator=)")
        found: dict[str, str] = {}
        for line in out.splitlines():  # newest first: the latest commit claiming a sha wins
            p = line.split()
            if len(p) == 2:
                found.setdefault(p[1], p[0])
        return found

    def push(self, tags: list[str]) -> None:
        b = self.s.git_branch
        for attempt in range(3):
            if self.ok("push", "-q", "origin", f"HEAD:refs/heads/{b}", remote=True):
                break
            self.git("fetch", "-q", "origin", remote=True)
            if not self.ok("rebase", "-q", f"origin/{b}"):
                self.git("rebase", "--abort", check=False)
                raise GitError(f"Push rejected and rebase onto origin/{b} failed")
            if attempt == 2:
                self.git("push", "-q", "origin", f"HEAD:refs/heads/{b}", remote=True)
        if tags:
            self.git(
                "push", "-q", "--force", "origin", *[f"refs/tags/{t}" for t in tags], remote=True
            )


def path_for(db: Session, c: ConfigCommit) -> tuple[str, str]:
    if c.l3_id:
        l3 = db.get(L3UseCase, c.l3_id)
        l2 = l3.parent
        code = l3.code
        rel = f"usecases/{l2.parent.code}/{l2.code}/{l3.code}.json"
    else:
        # L2 configurations from before issue #25: only kept for commits already in git
        l2 = db.get(L2UseCase, c.l2_id)
        code = l2.code
        rel = f"usecases/{l2.parent.code}/{l2.code}/{l2.code}.yaml"
    return code, rel


def legacy_path(rel: str) -> str | None:
    """Where the same configuration was stored while configurations were YAML."""
    return rel[: -len(".json")] + ".yaml" if rel.endswith(".json") else None


README = """# MaGMa use case configurations

This repository is written by Vulcan UCF, the MaGMa use case management web application. Every
configuration commit made in the app appears here as a git commit with the same author, date
and message. Tags are named `<use case>/<tag>`, for example `AO-CRE-01/verified-2026-11-13`.

Layout: `usecases/<L1>/<L2>/<L3>.json` for an L3 rule. When two-way sync is on in the app,
commits pushed here that change these files are read back into the app (valid JSON only,
existing rules only); otherwise changes made directly in this repository are not read back.
"""


PATH_RE = re.compile(r"^usecases/([^/]+)/([^/]+)/([^/]+)\.json$")


def owner_for(db: Session, path: str) -> L2UseCase | L3UseCase | None:
    """The use case a repository path belongs to (the inverse of path_for)."""
    m = PATH_RE.match(path)
    if not m:
        return None
    l1, l2, name = m.groups()
    obj = db.scalar(select(L3UseCase).where(L3UseCase.code == name))
    return obj if obj and obj.parent.code == l2 and obj.parent.parent.code == l1 else None


def import_remote(db: Session, repo: Repo, settings: Settings, res: Result, exported: set) -> None:
    """Read config changes that people pushed to the branch back into the app (two-way sync)."""
    st = state(db)
    head = repo.remote_head()
    if head is None or head == st.last_imported_sha:
        return
    since = st.last_imported_sha
    if since and not repo.ok("merge-base", "--is-ancestor", since, head):
        since = None  # history was rewritten: look at everything again (content checks below)
    rng = f"{since}..{head}" if since else head
    out = repo.git("log", "--reverse", "--format=%H", rng)
    shas = out.split()

    # per config file: the people's commits after the last commit the app wrote to it
    known = set(db.scalars(select(ConfigCommit.sha)))
    changes: dict[str, list[tuple[str, str]]] = {}
    for sha in shas:
        body = repo.git("show", "-s", "--format=%(trailers:key=" + TRAILER + ",valueonly)", sha)
        # anyone can write the trailer: only one naming a real app commit marks an app commit
        body = " ".join(v for v in body.split() if v in known)
        files = repo.git(
            "diff-tree", "--no-commit-id", "--root", "-r", "--name-status", "--no-renames", sha
        )
        for line in files.splitlines():
            status, _, path = line.partition("\t")
            if not PATH_RE.match(path):
                continue
            if body.strip():
                changes.pop(path, None)  # the app wrote this file later: earlier edits are in it
            else:
                changes.setdefault(path, []).append((sha, status))

    unsynced = {
        (c.l2_id, c.l3_id)
        for c in db.scalars(select(ConfigCommit).where(ConfigCommit.source != "git"))
        if c.sha not in exported
    }
    for path, commits in changes.items():
        obj = owner_for(db, path)
        if obj is None:
            res.notes.append(f"{path}: no such use case in the app, not imported")
            continue
        key = (obj.id, None) if isinstance(obj, L2UseCase) else (None, obj.id)
        if key in unsynced:
            res.notes.append(
                f"{obj.code}: changed in the app and in git ({commits[-1][0][:7]}); "
                "the app version was kept and pushed on top"
            )
            continue
        for sha, status in commits:
            content = "" if status == "D" else repo.git("show", f"{sha}:{path}", raw=True)
            check = configs.check_json(content)
            if not check.valid:
                where = f" (line {check.line})" if check.line else ""
                res.notes.append(f"{obj.code}: git commit {sha[:7]} is not valid JSON{where}")
                continue
            current = configs.head(db, obj)
            if (current.content if current else "").strip() == content.strip():
                continue
            name, when, subject = repo.git("show", "-s", "--format=%an%x00%aI%x00%s", sha).split(
                "\0"
            )
            c = configs.make_commit(
                db,
                obj,
                content,
                (subject or "Change in git")[:500],
                # the git author is self-asserted: mark it so it cannot pose as an app user
                f"git:{name or 'unknown'}"[:64],
                at=datetime.fromisoformat(when),
            )
            c.source, c.git_sha = "git", sha
            audit.record(
                db,
                None,
                "config_import",
                "l2" if key[0] else "l3",
                obj.code,
                {"git_sha": sha, "rev": c.rev, "author": c.author},
            )
            res.imported += 1
    st.last_imported_sha = head
    st.last_import_at = datetime.now(UTC)
    st.import_notes = res.notes[-50:]
    db.info.pop("git_dirty", None)  # nothing new to export because of the import itself


def verified_exports(db: Session, repo: Repo, done: dict[str, str], res: Result) -> dict[str, str]:
    """Drop trailer claims that do not hold: anyone with push access can write a `Magma-Commit`
    trailer. A claim is accepted when the app recorded that git commit itself, or when the file
    in that git commit has exactly the content of the app commit (then it is in git anyway)."""
    out = {}
    for c in db.scalars(select(ConfigCommit).where(ConfigCommit.sha.in_(list(done)))):
        git_sha = done[c.sha]
        if c.git_sha == git_sha:
            out[c.sha] = git_sha
            continue
        _, rel = path_for(db, c)
        content = ""
        # commits exported while configurations were YAML are in the .yaml file
        for path in (rel, legacy_path(rel)):
            if path and repo.ok("cat-file", "-e", f"{git_sha}:{path}"):
                content = repo.git("show", f"{git_sha}:{path}", raw=True)
                break
        if content.strip() == c.content.strip():
            out[c.sha] = git_sha
        else:
            res.notes.append(
                f"git commit {git_sha[:7]} claims app commit {c.sha[:7]} but its content "
                "differs; exported again"
            )
    return out


def sync(db: Session, settings: Settings) -> Result:
    repo = Repo(settings)
    repo.prepare()
    res = Result()
    done = repo.exported()
    if settings.git_pull:
        import_remote(db, repo, settings, res, set(done))
        db.flush()
    done = verified_exports(db, repo, done, res)
    todo = [
        c
        for c in db.scalars(select(ConfigCommit).order_by(ConfigCommit.created_at, ConfigCommit.id))
        if c.sha not in done and c.source != "git" and c.l3_id is not None
    ]
    readme = repo.dir / "README.md"
    if not readme.exists():
        readme.write_text(README)
        repo.git("add", "README.md")
        repo.git("commit", "-q", "-m", "Add README")
    for c in todo:
        code, rel = path_for(db, c)
        f = repo.dir / rel
        old = legacy_path(rel)
        if old and (repo.dir / old).exists():
            repo.git("rm", "-q", "--", old)  # the YAML file of this rule becomes the .json file
        if c.content.strip():
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(c.content if c.content.endswith("\n") else c.content + "\n")
            repo.git("add", "--", rel)
        elif f.exists():
            repo.git("rm", "-q", "--", rel)
        when = c.created_at if c.created_at.tzinfo else c.created_at.replace(tzinfo=UTC)
        msg = f"{code}: {c.message}\n\nRevision r{c.rev} in MaGMa UCF.\n\n{TRAILER}: {c.sha}"
        repo.git(
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            msg,
            env={
                "GIT_AUTHOR_NAME": c.author,
                "GIT_AUTHOR_EMAIL": f"{c.author}@{settings.git_author_email_domain}",
                "GIT_AUTHOR_DATE": when.isoformat(),
            },
        )
        res.exported += 1

    done = verified_exports(db, repo, repo.exported(), res)
    wanted: dict[str, str] = {}
    for t in db.scalars(select(ConfigTag)):
        c = t.commit
        code, _ = path_for(db, c)
        name = f"{code}/{t.name}"
        if c.sha in done and repo.ok("check-ref-format", f"refs/tags/{name}"):
            wanted[name] = done[c.sha]
    local = set(repo.git("tag", "--list").splitlines())
    changed = []
    for name, sha in wanted.items():
        if name not in local or repo.git("rev-list", "-n1", name) != sha:
            repo.git("tag", "-f", name, sha)
            changed.append(name)
    # only tags on commits the app exported; tags people set on their own commits stay
    ours = set(done.values())
    stale = [
        t
        for t in local
        if OUR_TAG.match(t) and t not in wanted and repo.git("rev-list", "-n1", t) in ours
    ]
    repo.push(changed)
    if stale:
        repo.git("push", "-q", "origin", *[f":refs/tags/{t}" for t in stale], remote=True)
        repo.git("tag", "-d", *stale)
    res.tags = len(changed)

    # record the git ids (they can change when a rebase was needed before the push)
    done = verified_exports(db, repo, repo.exported(), res)
    for c in db.scalars(select(ConfigCommit).where(ConfigCommit.source != "git")):
        if done.get(c.sha) != c.git_sha:
            c.git_sha = done.get(c.sha)
    res.head = repo.git("rev-parse", "HEAD")
    return res


def state(db: Session) -> GitSyncState:
    st = db.get(GitSyncState, 1)
    if st is None:
        st = GitSyncState(id=1)
        db.add(st)
    return st


_lock = threading.Lock()
_pending = threading.Event()
_running = threading.Event()


def run(factory: sessionmaker, settings: Settings) -> Result | None:
    """One sync with its outcome stored in git_sync_state. Raises nothing."""
    with _lock:
        _running.set()
        try:
            with factory() as db:
                if not try_job_lock(db, "gitsync"):
                    return None  # another replica is syncing
                st = state(db)
                st.last_attempt_at = datetime.now(UTC)
                try:
                    res = sync(db, settings)
                except (GitError, OSError, subprocess.TimeoutExpired) as e:
                    db.rollback()
                    st = state(db)
                    st.last_attempt_at = datetime.now(UTC)
                    st.last_error = str(e)[:2000]
                    db.commit()
                    log.warning("Git sync failed: %s", e)
                    return None
                st.last_success_at = st.last_attempt_at
                st.last_error = None
                st.head_sha = res.head
                db.commit()
                if res.exported or res.tags or res.imported:
                    log.info(
                        "Git sync: %d commits out, %d in, %d tags",
                        res.exported,
                        res.imported,
                        res.tags,
                    )
                return res
        finally:
            _running.clear()


def request(factory: sessionmaker, settings: Settings) -> None:
    """Sync in the background; several requests while a sync runs lead to one more run."""
    if not settings.git_enabled:
        return
    _pending.set()
    if _running.is_set():
        return

    def worker() -> None:
        while _pending.is_set():
            _pending.clear()
            run(factory, settings)

    threading.Thread(target=worker, name="gitsync", daemon=True).start()


def running() -> bool:
    return _running.is_set()


class Poller:
    """Two-way sync: look for new commits in the repository every few minutes."""

    def __init__(self, factory: sessionmaker, settings: Settings):
        self.factory, self.settings = factory, settings
        self._stop = threading.Event()

    def start(self) -> None:
        s = self.settings
        if not (s.git_enabled and s.git_pull and s.git_pull_interval_minutes > 0):
            return
        threading.Thread(target=self._loop, name="gitpoll", daemon=True).start()

    def _loop(self) -> None:
        while not self._stop.wait(self.settings.git_pull_interval_minutes * 60):
            request(self.factory, self.settings)

    def stop(self) -> None:
        self._stop.set()
