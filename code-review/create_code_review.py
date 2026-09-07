#!/usr/bin/env python3
"""
AWS Security Agent - Code Review 생성 TUI (curses / boto3).

연결할 Repository 가 많을 때 CLI 에서 쉽게 골라 Code Review 를 만들기 위한 도구.

흐름:
  1) Agent Space 선택 (--agent-space-id 로 건너뛸 수 있음)
  2) Integration(SOURCE_CODE) 목록 조회 - name + integrationId 함께 표시
  3) Integrated Repository 다중 선택 (Space 토글 / a 전체 / / 필터 / b 브랜치)
  4) 옵션 입력 (title, branch, remediation, validation, maxTaskHours, serviceRole)
  5) 최종 승인 -> CreateCodeReview
  6) 생성 후 실행 여부 확인 -> StartCodeReviewJob + 진행 상태 폴링

serviceRole 은 기존 Code Review / Pentest / Agent Space 의 IAM role 에서 자동 추론하며,
--service-role 로 직접 지정하거나 옵션 화면에서 수정할 수 있습니다.
"""

from __future__ import annotations

import argparse
import curses
import itertools
import json
import os
import shlex
import shutil
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, NoReturn, Sequence

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
except ImportError:  # pragma: no cover
    sys.exit("boto3 가 필요합니다:  pip install boto3")


DEFAULT_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
DEFAULT_BRANCH = "main"
DEFAULT_POLL_SECONDS = 15

REMEDIATION_CHOICES = ("DISABLED", "AUTOMATIC")
VALIDATION_CHOICES = ("(unset)", "DISABLED", "SIMULATED")

STEP_ORDER = ("PREFLIGHT", "STATIC_ANALYSIS", "PENTEST", "FINALIZING", "VALIDATION")
TERMINAL_JOB_STATUS = ("COMPLETED", "FAILED", "STOPPED")

PROVIDER_KEYS = {
    "githubRepository": ("GITHUB", "owner"),
    "gitlabRepository": ("GITLAB", "namespace"),
    "bitbucketRepository": ("BITBUCKET", "workspace"),
}
CAPABILITY_KEYS = {"GITHUB": "github", "GITLAB": "gitlab", "BITBUCKET": "bitbucket"}


# --------------------------------------------------------------------------- #
# 터미널(비 curses) 출력 helpers
# --------------------------------------------------------------------------- #

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    HEADER = "\033[1;96m"
    OK = "\033[32m"
    WARN = "\033[33m"
    ERR = "\033[31m"
    INFO = "\033[36m"
    ID = "\033[38;5;244m"
    LABEL = "\033[38;5;110m"


def disable_colors() -> None:
    for k, v in list(vars(C).items()):
        if isinstance(v, str) and v.startswith("\033"):
            setattr(C, k, "")


def use_colors(choice: str) -> bool:
    if choice == "always":
        return True
    if choice == "never":
        return False
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def term_width(default: int = 100) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except OSError:
        return default


class Spinner:
    """stderr 한 줄 스피너. 비 TTY 에서는 phase 당 한 줄만 출력."""

    FRAMES = ["|", "/", "-", "\\"]

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.is_tty = enabled and sys.stderr.isatty()
        self._label = ""
        self._stop: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def _render(self, frame: str) -> None:
        line = f"{frame} {self._label}"
        width = max(10, term_width() - 1)
        if len(line) > width:
            line = line[: width - 3] + "..."
        sys.stderr.write("\r\x1b[2K" + line)
        sys.stderr.flush()

    def _loop(self) -> None:
        assert self._stop is not None
        for frame in itertools.cycle(self.FRAMES):
            if self._stop.is_set():
                break
            with self._lock:
                self._render(frame)
            if self._stop.wait(0.12):
                break

    def start(self, label: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._label = label
        if not self.is_tty:
            sys.stderr.write(label + "\n")
            sys.stderr.flush()
            return
        if self._thread is None:
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def update(self, label: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._label = label
        if not self.is_tty:
            sys.stderr.write(label + "\n")
            sys.stderr.flush()

    def stop(self, msg: str | None = None) -> None:
        if not self.enabled:
            return
        if self._thread is not None:
            assert self._stop is not None
            self._stop.set()
            self._thread.join(timeout=0.5)
            self._thread = None
            self._stop = None
        if self.is_tty:
            sys.stderr.write("\r\x1b[2K")
        if msg:
            sys.stderr.write(msg + "\n")
        sys.stderr.flush()


def fatal(msg: str) -> NoReturn:
    sys.stderr.write(f"{C.ERR}오류:{C.RESET} {msg}\n")
    raise SystemExit(1)


# --------------------------------------------------------------------------- #
# 데이터 모델
# --------------------------------------------------------------------------- #

@dataclass
class Integration:
    integration_id: str
    display_name: str
    provider: str
    provider_type: str
    installation_id: str = ""
    target_url: str = ""

    @property
    def label(self) -> str:
        return f"{self.display_name}  ({self.integration_id})"


@dataclass
class Repo:
    integration_id: str
    integration_name: str
    provider: str
    name: str
    namespace: str            # github owner / gitlab namespace / bitbucket workspace
    provider_resource_id: str
    access_type: str = ""
    remediate_code: bool = False
    leave_comments: bool = False
    branch: str = DEFAULT_BRANCH
    selected: bool = False

    @property
    def full_name(self) -> str:
        return f"{self.namespace}/{self.name}" if self.namespace else self.name

    @property
    def search_blob(self) -> str:
        return " ".join(
            [self.full_name, self.provider_resource_id, self.integration_id,
             self.integration_name, self.provider, self.branch]
        ).lower()


@dataclass
class ReviewOptions:
    title: str
    branch: str = DEFAULT_BRANCH
    remediation: str = "DISABLED"
    validation: str = "(unset)"
    max_task_hours: str = ""          # 빈 문자열이면 미지정
    service_role: str = ""


@dataclass
class AgentSpaceRef:
    agent_space_id: str
    name: str
    created_at: Any = None


# --------------------------------------------------------------------------- #
# AWS API 계층 (boto3)
# --------------------------------------------------------------------------- #

class Api:
    def __init__(self, region: str, profile: str | None = None) -> None:
        try:
            session = boto3.session.Session(profile_name=profile, region_name=region)
            self.client = session.client(
                "securityagent",
                config=Config(retries={"max_attempts": 5, "mode": "standard"}),
            )
        except Exception as exc:  # 프로필/리전 오류 등
            fatal(f"securityagent 클라이언트 생성 실패: {exc}")
        self.region = region

    # -- 공통 -------------------------------------------------------------- #

    def paginate(
        self,
        op: str,
        items_key: str,
        on_page: Callable[[int, int], None] | None = None,
        **kwargs: Any,
    ) -> list[dict]:
        fn = getattr(self.client, op)
        items: list[dict] = []
        token: str | None = None
        page = 0
        while True:
            page += 1
            params = {k: v for k, v in kwargs.items() if v is not None}
            if token:
                params["nextToken"] = token
            if on_page:
                on_page(page, len(items))
            resp = fn(**params)
            items.extend(resp.get(items_key) or [])
            token = resp.get("nextToken")
            if not token:
                break
        return items

    # -- Agent Space ------------------------------------------------------- #

    def list_agent_spaces(self) -> list[AgentSpaceRef]:
        rows = self.paginate("list_agent_spaces", "agentSpaceSummaries")
        spaces = [
            AgentSpaceRef(
                agent_space_id=r.get("agentSpaceId", ""),
                name=r.get("name", ""),
                created_at=r.get("createdAt"),
            )
            for r in rows
            if r.get("agentSpaceId")
        ]
        spaces.sort(key=lambda s: (s.name or "").lower())
        return spaces

    def describe_agent_space(self, agent_space_id: str) -> dict:
        resp = self.client.batch_get_agent_spaces(agentSpaceIds=[agent_space_id])
        spaces = resp.get("agentSpaces") or []
        if not spaces:
            not_found = ", ".join(resp.get("notFound") or [agent_space_id])
            fatal(f"Agent Space 를 찾을 수 없습니다: {not_found}")
        return spaces[0]

    # -- Integration / Repository ------------------------------------------ #

    def list_source_integrations(self) -> list[Integration]:
        rows = self.paginate(
            "list_integrations",
            "integrationSummaries",
            filter={"providerType": "SOURCE_CODE"},
        )
        out = [
            Integration(
                integration_id=r.get("integrationId", ""),
                display_name=r.get("displayName", "") or "(no name)",
                provider=r.get("provider", ""),
                provider_type=r.get("providerType", ""),
                installation_id=r.get("installationId", "") or "",
                target_url=r.get("targetUrl", "") or "",
            )
            for r in rows
            if r.get("integrationId")
        ]
        out.sort(key=lambda i: (i.display_name or "").lower())
        return out

    def list_repos(
        self,
        agent_space_id: str,
        integration: Integration,
        on_page: Callable[[int, int], None] | None = None,
    ) -> list[Repo]:
        rows = self.paginate(
            "list_integrated_resources",
            "integratedResourceSummaries",
            on_page=on_page,
            agentSpaceId=agent_space_id,
            integrationId=integration.integration_id,
            resourceType="CODE_REPOSITORY",
        )
        repos: list[Repo] = []
        for row in rows:
            repo = _normalize_repo(row, integration)
            if repo:
                repos.append(repo)
        return repos

    # -- serviceRole 추론 --------------------------------------------------- #

    def detect_service_role(self, agent_space_id: str,
                            note: Callable[[str], None] | None = None) -> tuple[str, str]:
        """(role_arn, 출처) 를 반환. 찾지 못하면 ("", "")."""
        def say(msg: str) -> None:
            if note:
                note(msg)

        # 1) 같은 Agent Space 의 기존 Code Review
        try:
            say("serviceRole 추론: 기존 Code Review 조회")
            summaries = self.paginate(
                "list_code_reviews", "codeReviewSummaries", agentSpaceId=agent_space_id
            )
            summaries.sort(key=lambda s: _ts(s.get("createdAt")), reverse=True)
            for chunk in _chunks([s["codeReviewId"] for s in summaries if s.get("codeReviewId")], 10):
                resp = self.client.batch_get_code_reviews(
                    agentSpaceId=agent_space_id, codeReviewIds=chunk
                )
                items = sorted(
                    resp.get("codeReviews") or [],
                    key=lambda r: _ts(r.get("createdAt")),
                    reverse=True,
                )
                for item in items:
                    role = (item.get("serviceRole") or "").strip()
                    if role:
                        return role, f"기존 Code Review '{item.get('title', '')}'"
        except (ClientError, BotoCoreError):
            pass

        # 2) 같은 Agent Space 의 기존 Pentest
        try:
            say("serviceRole 추론: 기존 Pentest 조회")
            summaries = self.paginate(
                "list_pentests", "pentestSummaries", agentSpaceId=agent_space_id
            )
            summaries.sort(key=lambda s: _ts(s.get("createdAt")), reverse=True)
            for chunk in _chunks([s["pentestId"] for s in summaries if s.get("pentestId")], 10):
                resp = self.client.batch_get_pentests(
                    agentSpaceId=agent_space_id, pentestIds=chunk
                )
                items = sorted(
                    resp.get("pentests") or [],
                    key=lambda r: _ts(r.get("createdAt")),
                    reverse=True,
                )
                for item in items:
                    role = (item.get("serviceRole") or "").strip()
                    if role:
                        return role, f"기존 Pentest '{item.get('title', '')}'"
        except (ClientError, BotoCoreError):
            pass

        # 3) Agent Space 에 등록된 IAM role
        try:
            say("serviceRole 추론: Agent Space IAM role 조회")
            space = self.client.batch_get_agent_spaces(agentSpaceIds=[agent_space_id])
            for item in space.get("agentSpaces") or []:
                roles = ((item.get("awsResources") or {}).get("iamRoles")) or []
                for role in roles:
                    if role and ":role/" in role:
                        return role, "Agent Space awsResources.iamRoles"
        except (ClientError, BotoCoreError):
            pass

        return "", ""

    # -- 생성 / 실행 -------------------------------------------------------- #

    def create_code_review(self, agent_space_id: str, opts: ReviewOptions,
                           repos: Sequence[Repo]) -> dict:
        return self.client.create_code_review(**build_create_params(agent_space_id, opts, repos))

    def start_code_review_job(self, agent_space_id: str, code_review_id: str) -> dict:
        return self.client.start_code_review_job(
            agentSpaceId=agent_space_id, codeReviewId=code_review_id
        )

    def get_code_review_job(self, agent_space_id: str, job_id: str) -> dict:
        resp = self.client.batch_get_code_review_jobs(
            agentSpaceId=agent_space_id, codeReviewJobIds=[job_id]
        )
        jobs = resp.get("codeReviewJobs") or []
        return jobs[0] if jobs else {}

    def list_job_tasks(self, agent_space_id: str, job_id: str) -> list[dict]:
        return self.paginate(
            "list_code_review_job_tasks",
            "codeReviewJobTaskSummaries",
            agentSpaceId=agent_space_id,
            codeReviewJobId=job_id,
        )


def _normalize_repo(row: dict, integration: Integration) -> Repo | None:
    resource = row.get("resource") or {}
    caps = row.get("capabilities") or {}
    for key, (provider, ns_field) in PROVIDER_KEYS.items():
        meta = resource.get(key)
        if not meta:
            continue
        cap = caps.get(CAPABILITY_KEYS.get(provider, ""), {}) or {}
        return Repo(
            integration_id=row.get("integrationId") or integration.integration_id,
            integration_name=integration.display_name,
            provider=provider,
            name=meta.get("name", ""),
            namespace=meta.get(ns_field, "") or "",
            provider_resource_id=str(meta.get("providerResourceId", "")),
            access_type=meta.get("accessType", "") or "",
            remediate_code=bool(cap.get("remediateCode")),
            leave_comments=bool(cap.get("leaveComments")),
        )
    return None


def _chunks(seq: Sequence[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(seq), size):
        yield list(seq[i : i + size])


def _ts(value: Any) -> float:
    if isinstance(value, datetime):
        return value.timestamp()
    return 0.0


def build_create_params(agent_space_id: str, opts: ReviewOptions,
                        repos: Sequence[Repo]) -> dict:
    """CreateCodeReview 파라미터를 만든다 (boto3 / CLI 미리보기 공용)."""
    params: dict[str, Any] = {
        "title": opts.title,
        "agentSpaceId": agent_space_id,
        "assets": {
            "integratedRepositories": [
                {
                    "integrationId": r.integration_id,
                    "providerResourceId": r.provider_resource_id,
                    "branch": r.branch or opts.branch or DEFAULT_BRANCH,
                }
                for r in repos
            ]
        },
        "codeRemediationStrategy": opts.remediation,
    }
    role = (opts.service_role or "").strip()
    if role:
        params["serviceRole"] = role
    if opts.validation and opts.validation != "(unset)":
        params["validationMode"] = opts.validation
    hours = (opts.max_task_hours or "").strip()
    if hours:
        try:
            params["maxTaskHours"] = float(hours)
        except ValueError:
            pass
    return params


def cli_preview(region: str, agent_space_id: str, opts: ReviewOptions,
                repos: Sequence[Repo]) -> str:
    """동일한 작업을 수행하는 aws CLI 명령 미리보기."""
    params = build_create_params(agent_space_id, opts, repos)
    lines = [
        "aws securityagent create-code-review \\",
        f"  --region {shlex.quote(region)} \\",
        f"  --agent-space-id {shlex.quote(params['agentSpaceId'])} \\",
        f"  --title {shlex.quote(params['title'])} \\",
        f"  --code-remediation-strategy {params['codeRemediationStrategy']} \\",
    ]
    if "serviceRole" in params:
        lines.append(f"  --service-role {shlex.quote(params['serviceRole'])} \\")
    if "validationMode" in params:
        lines.append(f"  --validation-mode {params['validationMode']} \\")
    if "maxTaskHours" in params:
        lines.append(f"  --max-task-hours {params['maxTaskHours']} \\")
    assets = json.dumps(params["assets"], indent=2, ensure_ascii=False)
    lines.append(f"  --assets {shlex.quote(assets)}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# curses UI 기반 요소
# --------------------------------------------------------------------------- #

class Cancelled(Exception):
    """사용자가 ESC / q 로 취소."""


class GoBack(Exception):
    """이전 화면으로."""


CP_HEADER = 1
CP_CURSOR = 2
CP_DIM = 3
CP_OK = 4
CP_WARN = 5
CP_ERR = 6
CP_ID = 7
CP_ACCENT = 8


def init_colors() -> bool:
    if not curses.has_colors():
        return False
    curses.start_color()
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        bg = curses.COLOR_BLACK
    curses.init_pair(CP_HEADER, curses.COLOR_CYAN, bg)
    curses.init_pair(CP_CURSOR, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(CP_DIM, curses.COLOR_WHITE, bg)
    curses.init_pair(CP_OK, curses.COLOR_GREEN, bg)
    curses.init_pair(CP_WARN, curses.COLOR_YELLOW, bg)
    curses.init_pair(CP_ERR, curses.COLOR_RED, bg)
    curses.init_pair(CP_ID, curses.COLOR_BLUE, bg)
    curses.init_pair(CP_ACCENT, curses.COLOR_MAGENTA, bg)
    return True


class Ui:
    """curses 화면 그리기 helper."""

    def __init__(self, stdscr: "curses._CursesWindow", subtitle: str = "") -> None:
        self.scr = stdscr
        self.colors = init_colors()
        self.subtitle = subtitle
        curses.curs_set(0)
        stdscr.keypad(True)
        try:
            curses.set_escdelay(25)
        except (AttributeError, curses.error):
            pass

    # -- 저수준 ------------------------------------------------------------ #

    def attr(self, pair: int, bold: bool = False, dim: bool = False) -> int:
        a = curses.color_pair(pair) if self.colors else 0
        if bold:
            a |= curses.A_BOLD
        if dim:
            a |= curses.A_DIM
        return a

    @property
    def size(self) -> tuple[int, int]:
        h, w = self.scr.getmaxyx()
        return max(h, 5), max(w, 30)

    def put(self, y: int, x: int, text: str, attr: int = 0) -> None:
        h, w = self.size
        if y < 0 or y >= h or x >= w:
            return
        try:
            self.scr.addnstr(y, x, text, max(0, w - x - 1), attr)
        except curses.error:
            pass

    def hline(self, y: int, char: str = "─") -> None:
        _, w = self.size
        self.put(y, 0, char * (w - 1), self.attr(CP_DIM, dim=True))

    def header(self, title: str, right: str = "") -> int:
        _, w = self.size
        self.scr.erase()
        self.put(0, 0, title, self.attr(CP_HEADER, bold=True))
        if right:
            x = max(dwidth(title) + 2, w - 1 - dwidth(right))
            self.put(0, x, right, self.attr(CP_DIM, dim=True))
        if self.subtitle:
            self.put(1, 0, self.subtitle, self.attr(CP_DIM, dim=True))
            self.hline(2)
            return 3
        self.hline(1)
        return 2

    def footer(self, keys: str, note: str = "") -> None:
        h, _ = self.size
        self.hline(h - 2)
        self.put(h - 1, 0, keys, self.attr(CP_DIM, dim=True))
        if note:
            self.put(h - 1, min(dwidth(keys) + 3, self.size[1] - 2), note,
                     self.attr(CP_WARN))

    def flash(self, msg: str, pair: int = CP_WARN) -> None:
        h, _ = self.size
        self.put(h - 3, 0, " " * (self.size[1] - 1))
        self.put(h - 3, 0, fit(msg, self.size[1] - 2), self.attr(pair, bold=True))
        self.scr.refresh()

    def message(self, title: str, lines: Sequence[str], keys: str = "아무 키나 누르세요") -> None:
        top = self.header(title)
        for i, line in enumerate(lines):
            self.put(top + i, 2, line)
        self.footer(keys)
        self.scr.refresh()
        self.scr.getch()

    # -- 입력 -------------------------------------------------------------- #

    def edit_field(self, y: int, x: int, width: int, initial: str,
                   select_all: bool = False) -> str | None:
        """
        인라인 텍스트 편집. Enter=확정, ESC=취소(None).

        select_all=True 면 기본값이 '선택된' 상태(반전 표시)로 시작하고,
        첫 문자 입력이 기존 값을 전부 대체한다. 편집을 이어가려면
        ←/→/Backspace 등을 먼저 누르면 된다.
        """
        curses.curs_set(1)
        buf = list(initial)
        pos = len(buf)
        width = max(8, width)
        fresh = select_all and bool(initial)
        try:
            while True:
                text = "".join(buf)
                start = max(0, pos - (width - 2))
                view = text[start : start + width - 1]
                style = curses.A_REVERSE if fresh else curses.A_UNDERLINE
                self.put(y, x, view.ljust(width - 1), style)
                try:
                    self.scr.move(y, x + (pos - start))
                except curses.error:
                    pass
                self.scr.refresh()
                try:
                    ch = self.scr.get_wch()
                except curses.error:
                    continue
                except KeyboardInterrupt:
                    return None
                if isinstance(ch, str):
                    if ch in ("\n", "\r"):
                        return "".join(buf)
                    if ch == "\x1b":
                        return None
                    if ch in ("\x7f", "\b"):
                        fresh = False
                        if pos > 0:
                            del buf[pos - 1]
                            pos -= 1
                        continue
                    if ch == "\x15":            # Ctrl-U
                        buf, pos, fresh = [], 0, False
                        continue
                    if ch == "\x01":            # Ctrl-A
                        pos, fresh = 0, False
                        continue
                    if ch == "\x05":            # Ctrl-E
                        pos, fresh = len(buf), False
                        continue
                    if ch >= " ":
                        if fresh:
                            buf, pos, fresh = [], 0, False
                        buf.insert(pos, ch)
                        pos += 1
                    continue
                fresh = False
                if ch in (curses.KEY_BACKSPACE, curses.KEY_DC):
                    if ch == curses.KEY_DC:
                        if pos < len(buf):
                            del buf[pos]
                    elif pos > 0:
                        del buf[pos - 1]
                        pos -= 1
                elif ch == curses.KEY_LEFT:
                    pos = max(0, pos - 1)
                elif ch == curses.KEY_RIGHT:
                    pos = min(len(buf), pos + 1)
                elif ch == curses.KEY_HOME:
                    pos = 0
                elif ch == curses.KEY_END:
                    pos = len(buf)
                elif ch in (curses.KEY_ENTER,):
                    return "".join(buf)
        finally:
            curses.curs_set(0)

    def prompt(self, label: str, initial: str = "", width: int = 60) -> str | None:
        h, w = self.size
        y = h - 3
        self.put(y, 0, " " * (w - 1))
        self.put(y, 0, label, self.attr(CP_ACCENT, bold=True))
        lw = dwidth(label)
        return self.edit_field(y, lw + 1, min(width, w - lw - 3), initial,
                               select_all=True)

    def yes_no(self, question: str) -> bool:
        h, w = self.size
        y = h - 3
        self.put(y, 0, " " * (w - 1))
        self.put(y, 0, f"{question} [y/N] ", self.attr(CP_WARN, bold=True))
        self.scr.refresh()
        ch = self.scr.getch()
        return ch in (ord("y"), ord("Y"))

    def drain_escape(self) -> bool:
        """
        27(ESC) 을 읽은 직후 호출. 뒤따르는 바이트가 없으면 단독 ESC(True),
        있으면 미해석 이스케이프 시퀀스로 보고 모두 버린 뒤 False.
        """
        self.scr.nodelay(True)
        try:
            first = self.scr.getch()
            if first == -1:
                return True
            while self.scr.getch() != -1:
                pass
            return False
        finally:
            self.scr.nodelay(False)

    # -- 백그라운드 작업 + 진행 표시 ---------------------------------------- #

    def run_task(self, label: str, fn: Callable[[Callable[[str], None]], Any]) -> Any:
        """
        fn(set_status) 을 별도 스레드에서 실행하며 스피너를 돌린다.
        fn 이 예외를 던지면 그대로 다시 raise.
        """
        state: dict[str, Any] = {"status": label, "done": False,
                                 "result": None, "error": None}
        lock = threading.Lock()

        def set_status(msg: str) -> None:
            with lock:
                state["status"] = msg

        def worker() -> None:
            try:
                state["result"] = fn(set_status)
            except BaseException as exc:  # noqa: BLE001 - 호출자에게 전달
                state["error"] = exc
            finally:
                state["done"] = True

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

        frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        self.scr.nodelay(True)
        started = time.monotonic()
        i = 0
        try:
            while not state["done"]:
                top = self.header("작업 중…")
                with lock:
                    status = state["status"]
                elapsed = time.monotonic() - started
                self.put(top + 1, 2, f"{frames[i % len(frames)]}  {status}",
                         self.attr(CP_HEADER, bold=True))
                self.put(top + 3, 2, f"경과 {elapsed:,.0f}s", self.attr(CP_DIM, dim=True))
                self.footer("Ctrl-C 중단")
                self.scr.refresh()
                i += 1
                ch = self.scr.getch()
                if ch == 3:  # Ctrl-C
                    raise Cancelled()
                time.sleep(0.1)
        finally:
            self.scr.nodelay(False)
        thread.join(timeout=1)
        if state["error"] is not None:
            raise state["error"]
        return state["result"]


def dwidth(text: str) -> int:
    """터미널 표시 폭 (한글/한자 등 전각 문자는 2칸)."""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def fit(text: str, width: int) -> str:
    """표시 폭 기준으로 자른다 (넘치면 말줄임표)."""
    if width <= 0:
        return ""
    if dwidth(text) <= width:
        return text
    out, used = [], 0
    for ch in text:
        w = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if used + w > width - 1:
            break
        out.append(ch)
        used += w
    return "".join(out) + "…"


def pad(text: str, width: int) -> str:
    """표시 폭 기준 왼쪽 정렬 패딩 (필요하면 잘라낸다)."""
    text = fit(text, width)
    return text + " " * max(0, width - dwidth(text))


# --------------------------------------------------------------------------- #
# 목록 내비게이션 helpers
# --------------------------------------------------------------------------- #

def nav_key(key: int, cursor: int, count: int, page: int) -> int | None:
    if count == 0:
        return None
    if key in (curses.KEY_UP, ord("k")):
        return (cursor - 1) % count
    if key in (curses.KEY_DOWN, ord("j")):
        return (cursor + 1) % count
    if key == curses.KEY_NPAGE:
        return min(count - 1, cursor + page)
    if key == curses.KEY_PPAGE:
        return max(0, cursor - page)
    if key in (curses.KEY_HOME, ord("g")):
        return 0
    if key in (curses.KEY_END, ord("G")):
        return count - 1
    return None


def adjust_top(top: int, cursor: int, rows: int, count: int) -> int:
    if rows <= 0:
        return 0
    if cursor < top:
        top = cursor
    elif cursor >= top + rows:
        top = cursor - rows + 1
    return max(0, min(top, max(0, count - rows)))


def is_enter(key: int) -> bool:
    return key in (curses.KEY_ENTER, 10, 13)


def is_quit(ui: "Ui", key: int) -> bool:
    """q/Q, 또는 단독 ESC. 방향키 등 미해석 ESC 시퀀스는 종료로 보지 않는다."""
    if key in (ord("q"), ord("Q")):
        return True
    if key != 27:
        return False
    return ui.drain_escape()


# --------------------------------------------------------------------------- #
# 화면 1: Agent Space 선택
# --------------------------------------------------------------------------- #

def select_agent_space(ui: Ui, spaces: Sequence[AgentSpaceRef], region: str) -> AgentSpaceRef:
    if not spaces:
        ui.message("Agent Space 없음", [f"{region} 리전에 Agent Space 가 없습니다."])
        raise Cancelled()
    if len(spaces) == 1:
        return spaces[0]

    cursor, top = 0, 0
    query = ""
    while True:
        view = [s for s in spaces
                if not query or query.lower() in f"{s.name} {s.agent_space_id}".lower()]
        count = len(view)
        cursor = min(cursor, max(0, count - 1))
        h, w = ui.size
        title = f"Agent Space 선택  ({count}/{len(spaces)})"
        body = ui.header(title, f"region {region}")
        rows = max(1, h - body - 3)
        top = adjust_top(top, cursor, rows, count)

        if query:
            ui.put(body - 1, max(0, w - 24), f"filter: {fit(query, 14)}", ui.attr(CP_ACCENT))
        for i in range(rows):
            idx = top + i
            if idx >= count:
                break
            s = view[idx]
            selected = idx == cursor
            attr = ui.attr(CP_CURSOR) if selected else 0
            line = (f" {'▶' if selected else ' '} "
                    f"{pad(s.name, max(10, w - 48))}  {s.agent_space_id}")
            ui.put(body + i, 0, pad(line, w - 1), attr)
        if count == 0:
            ui.put(body, 2, "일치하는 Agent Space 가 없습니다.", ui.attr(CP_WARN))
        ui.footer("↑↓ 이동   Enter 선택   / 검색   q 종료")
        ui.scr.refresh()

        key = ui.scr.getch()
        moved = nav_key(key, cursor, count, rows)
        if moved is not None:
            cursor = moved
            continue
        if key == ord("/"):
            got = ui.prompt("검색:", query)
            if got is not None:
                query = got.strip()
                cursor, top = 0, 0
            continue
        if is_enter(key) and count:
            return view[cursor]
        if is_quit(ui, key):
            raise Cancelled()


# --------------------------------------------------------------------------- #
# 화면 2: Integration 선택 (다중, 기본 전체 선택)
# --------------------------------------------------------------------------- #

def select_integrations(ui: Ui, integrations: Sequence[Integration]) -> list[Integration]:
    if not integrations:
        ui.message(
            "Source code Integration 없음",
            [
                "SOURCE_CODE 타입 Integration 이 없습니다.",
                "Security Agent 콘솔에서 GitHub/GitLab/Bitbucket 연동을 먼저 추가하세요.",
            ],
        )
        raise Cancelled()
    if len(integrations) == 1:
        return list(integrations)

    chosen = {i.integration_id for i in integrations}
    cursor, top = 0, 0
    while True:
        count = len(integrations)
        h, w = ui.size
        body = ui.header(f"Integration 선택  ({len(chosen)}/{count} 선택됨)",
                         "Repository 를 가져올 연동")
        rows = max(1, h - body - 3)
        top = adjust_top(top, cursor, rows, count)

        name_w = max(16, (w - 1) - 4 - 40 - 12)
        for i in range(rows):
            idx = top + i
            if idx >= count:
                break
            it = integrations[idx]
            on = it.integration_id in chosen
            attr = ui.attr(CP_CURSOR) if idx == cursor else 0
            line = (
                f" [{'x' if on else ' '}] "
                f"{pad(it.display_name, name_w)}  "
                f"{it.integration_id:<40} {it.provider}"
            )
            ui.put(body + i, 0, pad(line, w - 1), attr)
        cur = integrations[cursor]
        detail = f"provider={cur.provider}  installationId={cur.installation_id or '-'}"
        if cur.target_url:
            detail += f"  url={cur.target_url}"
        ui.put(h - 3, 0, fit(detail, w - 2), ui.attr(CP_DIM, dim=True))
        ui.footer("Space 토글   a 전체   n 해제   Enter 다음   q 종료")
        ui.scr.refresh()

        key = ui.scr.getch()
        moved = nav_key(key, cursor, count, rows)
        if moved is not None:
            cursor = moved
            continue
        if key == ord(" "):
            iid = integrations[cursor].integration_id
            chosen.symmetric_difference_update({iid})
            continue
        if key in (ord("a"), ord("A")):
            chosen = {i.integration_id for i in integrations}
            continue
        if key in (ord("n"), ord("N")):
            chosen.clear()
            continue
        if is_enter(key):
            if not chosen:
                ui.flash("Integration 을 하나 이상 선택하세요.")
                continue
            return [i for i in integrations if i.integration_id in chosen]
        if is_quit(ui, key):
            raise Cancelled()


# --------------------------------------------------------------------------- #
# 화면 3: Repository 다중 선택
# --------------------------------------------------------------------------- #

def select_repos(ui: Ui, repos: list[Repo], default_branch: str) -> list[Repo]:
    if not repos:
        ui.message(
            "Repository 없음",
            [
                "선택한 Integration 에 연결된 CODE_REPOSITORY 리소스가 없습니다.",
                "Agent Space 에 Repository 를 먼저 연결하세요.",
            ],
        )
        raise Cancelled()

    cursor, top = 0, 0
    query = ""
    while True:
        view = [r for r in repos if not query or query.lower() in r.search_blob]
        count = len(view)
        cursor = min(cursor, max(0, count - 1))
        n_sel = sum(1 for r in repos if r.selected)
        h, w = ui.size
        body = ui.header(
            f"Repository 선택  ({n_sel}/{len(repos)} 선택됨)",
            f"filter: {fit(query, 20)}" if query else "",
        )
        rows = max(1, h - body - 5)
        top = adjust_top(top, cursor, rows, count)

        avail = w - 1
        id_w, br_w = 13, 12
        int_w = min(30, max(0, avail // 4))
        name_w = avail - 4 - id_w - br_w - int_w - 6
        if name_w < 16:
            int_w = 0
            name_w = max(12, avail - 4 - id_w - br_w - 4)

        ui.put(body, 5, f"{'REPOSITORY':<{name_w}}  {'RESOURCE ID':<{id_w}} "
                        f"{'BRANCH':<{br_w}} {'INTEGRATION' if int_w else ''}",
               ui.attr(CP_DIM, dim=True))
        body += 1
        for i in range(rows):
            idx = top + i
            if idx >= count:
                break
            r = view[idx]
            on_cursor = idx == cursor
            base = ui.attr(CP_CURSOR) if on_cursor else 0
            mark = "x" if r.selected else " "
            integ = f"{r.integration_name} ({r.integration_id[:10]}…)" if int_w else ""
            line = (
                f" [{mark}] "
                f"{pad(r.full_name, name_w)}  "
                f"{pad(r.provider_resource_id, id_w)} "
                f"{pad(r.branch, br_w)} "
                f"{fit(integ, int_w) if int_w else ''}"
            )
            attr = base
            if r.selected and not on_cursor:
                attr = ui.attr(CP_OK, bold=True)
            ui.put(body + i, 0, pad(line, w - 1), attr)
        if count == 0:
            ui.put(body, 2, "필터에 일치하는 Repository 가 없습니다.", ui.attr(CP_WARN))

        if count:
            cur = view[cursor]
            caps = []
            if cur.remediate_code:
                caps.append("remediateCode")
            if cur.leave_comments:
                caps.append("leaveComments")
            detail = (
                f"{cur.provider} · {cur.full_name} · providerResourceId={cur.provider_resource_id} "
                f"· integrationId={cur.integration_id} ({cur.integration_name})"
            )
            detail2 = f"access={cur.access_type or '-'}  capabilities={', '.join(caps) or '-'}"
            ui.put(h - 4, 0, fit(detail, w - 2), ui.attr(CP_ID))
            ui.put(h - 3, 0, fit(detail2, w - 2), ui.attr(CP_DIM, dim=True))
        ui.footer("Space 토글  a 전체  n 해제  / 필터  b 브랜치  B 선택전체브랜치  Enter 다음  q 종료")
        ui.scr.refresh()

        key = ui.scr.getch()
        moved = nav_key(key, cursor, count, rows)
        if moved is not None:
            cursor = moved
            continue
        if key == ord(" ") and count:
            view[cursor].selected = not view[cursor].selected
            cursor = min(cursor + 1, count - 1)
            continue
        if key == ord("a"):
            for r in view:
                r.selected = True
            continue
        if key == ord("n"):
            for r in view:
                r.selected = False
            continue
        if key == ord("/"):
            got = ui.prompt("필터:", query)
            if got is not None:
                query = got.strip()
                cursor, top = 0, 0
            continue
        if key == ord("b") and count:
            got = ui.prompt(f"'{view[cursor].full_name}' 브랜치:", view[cursor].branch)
            if got is not None and got.strip():
                view[cursor].branch = got.strip()
            continue
        if key == ord("B"):
            targets = [r for r in repos if r.selected] or view
            got = ui.prompt(f"브랜치 일괄 적용 ({len(targets)}개):", default_branch)
            if got is not None and got.strip():
                for r in targets:
                    r.branch = got.strip()
            continue
        if is_enter(key):
            picked = [r for r in repos if r.selected]
            if not picked:
                ui.flash("Repository 를 하나 이상 선택하세요 (Space 로 토글).")
                continue
            return picked
        if is_quit(ui, key):
            raise Cancelled()


# --------------------------------------------------------------------------- #
# 화면 4: 옵션 입력
# --------------------------------------------------------------------------- #

def options_form(ui: Ui, opts: ReviewOptions, repos: list[Repo],
                 role_source: str) -> ReviewOptions:
    fields: list[tuple[str, str, str]] = [
        ("title", "Title", "text"),
        ("branch", "Default branch", "text"),
        ("remediation", "Code remediation strategy", "enum"),
        ("validation", "Validation mode", "enum"),
        ("max_task_hours", "Max task hours (비우면 미지정)", "text"),
        ("service_role", "Service role ARN", "text"),
    ]
    cursor, top = 0, 0
    while True:
        h, w = ui.size
        body = ui.header("Code Review 옵션",
                         f"{len(repos)}개 Repository 선택됨")
        label_w = 30
        # 화면이 낮으면 행 간격을 줄이고, 그래도 부족하면 스크롤한다.
        avail = max(1, h - body - 3)
        step = 2 if avail >= len(fields) * 2 + 2 else 1
        visible = max(1, avail // step)
        top = adjust_top(top, cursor, visible, len(fields))
        for row, i in enumerate(range(top, min(top + visible, len(fields)))):
            key, label, kind = fields[i]
            value = getattr(opts, key)
            shown = value if value != "" else "(unset)"
            attr = ui.attr(CP_CURSOR) if i == cursor else 0
            y = body + row * step
            line = f" {pad(label, label_w)} {fit(str(shown), max(10, w - label_w - 6))}"
            ui.put(y, 0, pad(line, w - 1), attr)
            if i == cursor and kind == "enum" and step == 2:
                ui.put(y + 1, label_w + 2, "←/→ 또는 Enter 로 변경", ui.attr(CP_DIM, dim=True))
        if len(fields) > visible:
            ui.put(body - 1, max(0, w - 12),
                   f"{cursor + 1}/{len(fields)}", ui.attr(CP_DIM, dim=True))
        info_y = body + min(visible, len(fields)) * step + 1
        if role_source and opts.service_role and info_y < h - 2:
            ui.put(info_y, 2, fit(f"serviceRole 출처: {role_source}", w - 4),
                   ui.attr(CP_DIM, dim=True))
        if opts.remediation == "AUTOMATIC" and info_y + 1 < h - 2:
            no_cap = [r.full_name for r in repos if not r.remediate_code]
            if no_cap:
                ui.put(info_y + 1, 2,
                       fit(f"주의: remediateCode 권한이 없는 Repository {len(no_cap)}개 "
                           f"({', '.join(no_cap[:3])}{'…' if len(no_cap) > 3 else ''})", w - 4),
                       ui.attr(CP_WARN))
        ui.footer("↑↓ 이동   Enter 편집/변경   c 계속   q 이전 화면")
        ui.scr.refresh()

        key = ui.scr.getch()
        moved = nav_key(key, cursor, len(fields), 4)
        if moved is not None:
            cursor = moved
            continue
        name, label, kind = fields[cursor]
        if kind == "enum" and (key in (curses.KEY_LEFT, curses.KEY_RIGHT) or is_enter(key)):
            choices = REMEDIATION_CHOICES if name == "remediation" else VALIDATION_CHOICES
            cur_val = getattr(opts, name)
            idx = choices.index(cur_val) if cur_val in choices else 0
            step = -1 if key == curses.KEY_LEFT else 1
            setattr(opts, name, choices[(idx + step) % len(choices)])
            continue
        if kind == "text" and is_enter(key):
            got = ui.prompt(f"{label}:", str(getattr(opts, name)), width=w - 40)
            if got is None:
                continue
            got = got.strip()
            if name == "title" and not got:
                ui.flash("Title 은 비울 수 없습니다.")
                continue
            if name == "max_task_hours" and got:
                try:
                    if float(got) <= 0:
                        raise ValueError
                except ValueError:
                    ui.flash("Max task hours 는 0 보다 큰 숫자여야 합니다.")
                    continue
            if name == "branch" and got and got != opts.branch:
                setattr(opts, name, got)
                if ui.yes_no(f"모든 Repository 브랜치를 '{got}' 로 변경할까요?"):
                    for r in repos:
                        r.branch = got
                continue
            setattr(opts, name, got)
            continue
        if key in (ord("c"), ord("C")):
            if not opts.title.strip():
                ui.flash("Title 을 입력하세요.")
                continue
            return opts
        if is_quit(ui, key):
            raise GoBack()


# --------------------------------------------------------------------------- #
# 화면 5: 최종 확인
# --------------------------------------------------------------------------- #

def confirm_screen(ui: Ui, region: str, space: AgentSpaceRef,
                   opts: ReviewOptions, repos: list[Repo]) -> bool:
    lines: list[tuple[str, int]] = []

    def add(text: str = "", pair: int = 0, bold: bool = False, dim: bool = False) -> None:
        lines.append((text, ui.attr(pair, bold=bold, dim=dim) if pair or bold or dim else 0))

    add("생성될 Code Review", CP_HEADER, bold=True)
    add(f"  Region          : {region}")
    add(f"  Agent Space     : {space.name}  ({space.agent_space_id})")
    add(f"  Title           : {opts.title}")
    add(f"  Remediation     : {opts.remediation}")
    add(f"  Validation mode : {opts.validation if opts.validation != '(unset)' else '(미지정)'}")
    add(f"  Max task hours  : {opts.max_task_hours or '(미지정)'}")
    add(f"  Service role    : {opts.service_role or '(미지정)'}")
    add()
    add(f"Repositories ({len(repos)})", CP_HEADER, bold=True)
    for r in repos:
        add(f"  • {r.full_name}  [{r.branch}]", CP_OK)
        add(f"      integrationId={r.integration_id}  providerResourceId={r.provider_resource_id}",
            CP_ID)
    if opts.remediation == "AUTOMATIC":
        no_cap = [r.full_name for r in repos if not r.remediate_code]
        if no_cap:
            add()
            add(f"주의: remediateCode 권한 없는 Repository {len(no_cap)}개 - "
                f"{', '.join(no_cap)}", CP_WARN)
    if not opts.service_role:
        add()
        add("주의: serviceRole 미지정 상태로 생성됩니다.", CP_WARN)
    add()
    add("동일 작업 AWS CLI", CP_HEADER, bold=True)
    for cli_line in cli_preview(region, space.agent_space_id, opts, repos).splitlines():
        add("  " + cli_line, CP_DIM, dim=True)

    top = 0
    while True:
        h, w = ui.size
        body = ui.header("최종 확인", f"{len(repos)} repos")
        rows = max(1, h - body - 3)
        top = max(0, min(top, max(0, len(lines) - rows)))
        for i in range(rows):
            idx = top + i
            if idx >= len(lines):
                break
            text, attr = lines[idx]
            ui.put(body + i, 0, fit(text, w - 2), attr)
        more = f"{top + 1}-{min(top + rows, len(lines))}/{len(lines)}"
        ui.put(body - 1, max(0, w - 2 - dwidth(more)), more, ui.attr(CP_DIM, dim=True))
        ui.footer("y 생성   ↑↓/PgUp/PgDn 스크롤   b 이전 화면   q 취소")
        ui.scr.refresh()

        key = ui.scr.getch()
        if key in (curses.KEY_DOWN, ord("j")):
            top += 1
        elif key in (curses.KEY_UP, ord("k")):
            top -= 1
        elif key == curses.KEY_NPAGE:
            top += rows
        elif key == curses.KEY_PPAGE:
            top -= rows
        elif key == curses.KEY_HOME:
            top = 0
        elif key == curses.KEY_END:
            top = len(lines)
        elif key in (ord("y"), ord("Y")):
            return True
        elif key in (ord("b"), ord("B")):
            raise GoBack()
        elif is_quit(ui, key):
            return False


# --------------------------------------------------------------------------- #
# TUI 오케스트레이션
# --------------------------------------------------------------------------- #

@dataclass
class Plan:
    space: AgentSpaceRef
    opts: ReviewOptions
    repos: list[Repo]


def default_title() -> str:
    return "codereview-" + datetime.now().strftime("%Y%m%d-%H%M%S")


def _load_repos(api: Api, agent_space_id: str, integrations: Sequence[Integration],
                default_branch: str, set_status: Callable[[str], None]) -> list[Repo]:
    repos: list[Repo] = []
    total = len(integrations)
    for i, integ in enumerate(integrations, 1):
        def on_page(page: int, so_far: int, i=i, integ=integ) -> None:
            set_status(
                f"Repository 조회 {i}/{total} · {integ.display_name} "
                f"· page {page} · 누적 {len(repos) + so_far}개"
            )

        set_status(f"Repository 조회 {i}/{total} · {integ.display_name}")
        found = api.list_repos(agent_space_id, integ, on_page=on_page)
        for r in found:
            r.branch = default_branch or DEFAULT_BRANCH
        repos.extend(found)
    repos.sort(key=lambda r: (r.integration_name.lower(), r.full_name.lower()))
    return repos


def run_tui(stdscr: "curses._CursesWindow", api: Api, args: argparse.Namespace) -> Plan | None:
    ui = Ui(stdscr, subtitle=f"AWS Security Agent · Code Review 생성 · region {api.region}")

    # 1) Agent Space
    if args.agent_space_id:
        space_raw = ui.run_task(
            "Agent Space 조회",
            lambda _s: api.describe_agent_space(args.agent_space_id),
        )
        space = AgentSpaceRef(
            agent_space_id=space_raw.get("agentSpaceId", args.agent_space_id),
            name=space_raw.get("name", ""),
        )
    else:
        spaces = ui.run_task("Agent Space 목록 조회", lambda _s: api.list_agent_spaces())
        space = select_agent_space(ui, spaces, api.region)

    # 2) serviceRole 자동 추론
    role, role_source = ("", "")
    if args.service_role:
        role, role_source = args.service_role, "--service-role 옵션"
    else:
        role, role_source = ui.run_task(
            "serviceRole 추론",
            lambda s: api.detect_service_role(space.agent_space_id, note=s),
        )

    # 3) Integration
    integrations = ui.run_task("Integration 목록 조회", lambda _s: api.list_source_integrations())

    opts = ReviewOptions(
        title=args.title or default_title(),
        branch=args.branch,
        remediation=args.code_remediation_strategy,
        validation=args.validation_mode or "(unset)",
        max_task_hours="" if args.max_task_hours is None else str(args.max_task_hours),
        service_role=role,
    )

    stage = "integrations"
    chosen: list[Integration] = []
    repos: list[Repo] = []
    picked: list[Repo] = []
    while True:
        if stage == "integrations":
            chosen = select_integrations(ui, integrations)
            repos = ui.run_task(
                "Repository 조회",
                lambda s: _load_repos(api, space.agent_space_id, chosen, opts.branch, s),
            )
            stage = "repos"
        elif stage == "repos":
            picked = select_repos(ui, repos, opts.branch)
            stage = "options"
        elif stage == "options":
            try:
                opts = options_form(ui, opts, picked, role_source)
            except GoBack:
                stage = "repos"
                continue
            stage = "confirm"
        elif stage == "confirm":
            try:
                approved = confirm_screen(ui, api.region, space, opts, picked)
            except GoBack:
                stage = "options"
                continue
            if not approved:
                return None
            return Plan(space=space, opts=opts, repos=list(picked))


# --------------------------------------------------------------------------- #
# 생성 후: Job 실행 및 진행 상태 표시
# --------------------------------------------------------------------------- #

def fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def status_color(status: str) -> str:
    s = (status or "").upper()
    if s in ("COMPLETED",):
        return C.OK
    if s in ("FAILED", "STOPPED", "INTERNAL_ERROR", "ABORTED"):
        return C.ERR
    if s in ("IN_PROGRESS", "STOPPING", "NOT_STARTED"):
        return C.WARN
    return C.INFO


def print_step_table(job: dict) -> None:
    steps = job.get("steps") or []
    if not steps:
        return
    order = {name: i for i, name in enumerate(STEP_ORDER)}
    steps = sorted(steps, key=lambda s: order.get(s.get("name", ""), 99))
    print(f"  {C.LABEL}{'STEP':<18} {'STATUS':<14} {'DURATION':<12}{C.RESET}")
    for st in steps:
        name = st.get("name", "-")
        status = st.get("status", "-")
        created, updated = st.get("createdAt"), st.get("updatedAt")
        if isinstance(created, datetime):
            end = updated if isinstance(updated, datetime) else datetime.now(timezone.utc)
            if status in ("IN_PROGRESS", "NOT_STARTED"):
                end = datetime.now(timezone.utc)
            dur = fmt_duration((end - created).total_seconds())
        else:
            dur = "-"
        print(f"  {name:<18} {status_color(status)}{status:<14}{C.RESET} {dur:<12}")


def watch_job(api: Api, agent_space_id: str, job_id: str,
              poll_seconds: int = DEFAULT_POLL_SECONDS) -> str:
    """Job 이 종료 상태가 될 때까지 진행 상황을 표시. 최종 status 반환."""
    print()
    print(f"{C.HEADER}진행 상태 감시{C.RESET}  (Ctrl-C 로 감시만 중단, Job 은 계속 실행)")
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    is_tty = sys.stdout.isatty()
    started = time.monotonic()
    last_sig: tuple | None = None
    seen_context: set[tuple] = set()
    frame_i = 0
    status = "IN_PROGRESS"

    try:
        while True:
            job = api.get_code_review_job(agent_space_id, job_id)
            status = job.get("status", "UNKNOWN")
            steps = job.get("steps") or []
            sig = tuple((s.get("name"), s.get("status")) for s in steps) + (status,)

            try:
                tasks = api.list_job_tasks(agent_space_id, job_id)
            except (ClientError, BotoCoreError):
                tasks = []
            counts: dict[str, int] = {}
            for t in tasks:
                key = t.get("executionStatus", "UNKNOWN")
                counts[key] = counts.get(key, 0) + 1
            task_summary = "  ".join(f"{k.lower()}={v}" for k, v in sorted(counts.items()))

            if sig != last_sig:
                if is_tty:
                    sys.stdout.write("\r\x1b[2K")
                print()
                print(f"  {C.BOLD}[{datetime.now().strftime('%H:%M:%S')}]{C.RESET} "
                      f"job status: {status_color(status)}{status}{C.RESET}")
                print_step_table(job)
                last_sig = sig

            for ctx in job.get("executionContext") or []:
                key = (str(ctx.get("timestamp")), ctx.get("context", ""))
                if key in seen_context:
                    continue
                seen_context.add(key)
                ctype = ctx.get("contextType", "INFO")
                color = C.ERR if "ERROR" in ctype else (C.WARN if ctype == "WARNING" else C.INFO)
                if is_tty:
                    sys.stdout.write("\r\x1b[2K")
                print(f"  {color}{ctype}{C.RESET} {ctx.get('context', '')}")

            if status in TERMINAL_JOB_STATUS:
                if is_tty:
                    sys.stdout.write("\r\x1b[2K")
                    sys.stdout.flush()
                err = job.get("errorInformation") or {}
                if err:
                    print(f"  {C.ERR}error{C.RESET} [{err.get('code', '-')}] "
                          f"{err.get('message', '')}")
                if task_summary:
                    print(f"  tasks: {task_summary}")
                return status

            deadline = time.monotonic() + poll_seconds
            while time.monotonic() < deadline:
                if is_tty:
                    elapsed = fmt_duration(time.monotonic() - started)
                    line = (f"{frames[frame_i % len(frames)]} {status} · 경과 {elapsed}"
                            + (f" · tasks {task_summary}" if task_summary else "")
                            + f" · {int(deadline - time.monotonic()) + 1}s 후 갱신")
                    width = max(20, term_width() - 1)
                    sys.stdout.write("\r\x1b[2K" + line[:width])
                    sys.stdout.flush()
                    frame_i += 1
                time.sleep(0.15 if is_tty else 1.0)
    except KeyboardInterrupt:
        if is_tty:
            sys.stdout.write("\r\x1b[2K")
            sys.stdout.flush()
        print(f"{C.WARN}감시를 중단했습니다. Job 은 계속 실행됩니다.{C.RESET}")
        print("  상태 확인:")
        print(f"    aws securityagent batch-get-code-review-jobs --region {api.region} \\")
        print(f"      --agent-space-id {agent_space_id} --code-review-job-ids {job_id}")
        print("  중지:")
        print(f"    aws securityagent stop-code-review-job --region {api.region} \\")
        print(f"      --agent-space-id {agent_space_id} --code-review-job-id {job_id}")
        return status


# --------------------------------------------------------------------------- #
# CLI 진입점
# --------------------------------------------------------------------------- #

def ask_yes_no(question: str, default: bool = False) -> bool:
    if not sys.stdin.isatty():
        return default
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        answer = input(f"{C.WARN}{question} {suffix} {C.RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not answer:
        return default
    return answer in ("y", "yes")


def print_plan(plan: Plan, region: str) -> None:
    print()
    print(f"{C.HEADER}Code Review 생성 요약{C.RESET}")
    print(f"  {C.LABEL}region{C.RESET}         {region}")
    print(f"  {C.LABEL}agentSpaceId{C.RESET}   {plan.space.agent_space_id}"
          + (f"  ({plan.space.name})" if plan.space.name else ""))
    print(f"  {C.LABEL}title{C.RESET}          {plan.opts.title}")
    print(f"  {C.LABEL}remediation{C.RESET}    {plan.opts.remediation}")
    if plan.opts.validation != "(unset)":
        print(f"  {C.LABEL}validationMode{C.RESET} {plan.opts.validation}")
    if plan.opts.max_task_hours:
        print(f"  {C.LABEL}maxTaskHours{C.RESET}   {plan.opts.max_task_hours}")
    print(f"  {C.LABEL}serviceRole{C.RESET}    {plan.opts.service_role or '(미지정)'}")
    print(f"  {C.LABEL}repositories{C.RESET}   {len(plan.repos)}개")
    for r in plan.repos:
        print(f"    {C.OK}•{C.RESET} {r.full_name} [{r.branch}]  "
              f"{C.ID}providerResourceId={r.provider_resource_id} "
              f"integrationId={r.integration_id}{C.RESET}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="create_code_review.py",
        description="AWS Security Agent Code Review 를 curses TUI 로 생성/실행합니다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 전체 대화형 (Agent Space 부터 선택)
  ./create_code_review.py --region us-east-1

  # Agent Space 를 지정하고 Repository 만 골라서 생성
  ./create_code_review.py --agent-space-id as-f8f53636-865b-47e5-8603-2ecadfe0fdf3

  # 생성 후 바로 실행하고 진행 상태까지 감시
  ./create_code_review.py --agent-space-id as-... --title multi-repo-review --start

  # 실제로 만들지 않고 aws CLI 명령만 확인
  ./create_code_review.py --agent-space-id as-... --dry-run

키 조작:
  ↑↓/jk 이동   Space 토글   a 전체선택   n 전체해제   / 필터
  b 커서 브랜치   B 선택항목 브랜치 일괄   Enter 다음   q 취소/이전
""",
    )
    p.add_argument("--region", default=DEFAULT_REGION, help=f"기본값: {DEFAULT_REGION}")
    p.add_argument("--profile", default=None, help="AWS 프로필 이름")
    p.add_argument("--agent-space-id", default=None,
                   help="지정하면 Agent Space 선택 화면을 건너뜁니다")
    p.add_argument("--service-role", default=None,
                   help="미지정 시 기존 Code Review/Pentest/Agent Space 에서 자동 추론")
    p.add_argument("--title", default=None, help=f"기본값: {default_title()} 형식")
    p.add_argument("--branch", default=DEFAULT_BRANCH, help=f"기본 브랜치 (기본값: {DEFAULT_BRANCH})")
    p.add_argument("--code-remediation-strategy", choices=REMEDIATION_CHOICES,
                   default="DISABLED")
    p.add_argument("--validation-mode", choices=("DISABLED", "SIMULATED"), default=None)
    p.add_argument("--max-task-hours", type=float, default=None)
    start = p.add_mutually_exclusive_group()
    start.add_argument("--start", action="store_true",
                       help="생성 후 확인 없이 바로 Job 실행")
    start.add_argument("--no-start", action="store_true",
                       help="생성만 하고 실행 여부를 묻지 않음")
    p.add_argument("--no-watch", action="store_true",
                   help="Job 실행 후 진행 상태 감시를 하지 않음")
    p.add_argument("--poll-seconds", type=int, default=DEFAULT_POLL_SECONDS,
                   help=f"진행 상태 폴링 주기 (기본값: {DEFAULT_POLL_SECONDS}초)")
    p.add_argument("--dry-run", action="store_true",
                   help="생성하지 않고 aws CLI 명령만 출력")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not use_colors(args.color):
        disable_colors()
    if args.poll_seconds < 1:
        args.poll_seconds = 1

    if not sys.stdout.isatty() and not args.dry_run:
        sys.stderr.write(f"{C.WARN}경고: TTY 가 아니면 TUI 를 사용할 수 없습니다.{C.RESET}\n")

    api = Api(args.region, args.profile)

    try:
        plan = curses.wrapper(run_tui, api, args)
    except Cancelled:
        print(f"{C.WARN}취소했습니다.{C.RESET}")
        return 130
    except KeyboardInterrupt:
        print(f"{C.WARN}중단했습니다.{C.RESET}")
        return 130
    except NoCredentialsError:
        fatal("AWS 자격 증명을 찾을 수 없습니다. (aws configure / AWS_PROFILE 확인)")
    except ClientError as exc:
        fatal(f"API 호출 실패: {exc.response.get('Error', {}).get('Message', exc)}")
    except BotoCoreError as exc:
        fatal(f"API 호출 실패: {exc}")

    if plan is None:
        print(f"{C.WARN}취소했습니다. 생성하지 않았습니다.{C.RESET}")
        return 130

    print_plan(plan, api.region)

    print()
    print(f"{C.HEADER}동일 작업 AWS CLI{C.RESET}")
    print(cli_preview(api.region, plan.space.agent_space_id, plan.opts, plan.repos))

    if args.dry_run:
        print()
        print(f"{C.INFO}--dry-run: 실제로 생성하지 않았습니다.{C.RESET}")
        return 0

    if not ask_yes_no("\n위 내용으로 Code Review 를 생성할까요?", default=True):
        print(f"{C.WARN}취소했습니다.{C.RESET}")
        return 130

    spinner = Spinner(enabled=True)
    spinner.start("CreateCodeReview 호출 중…")
    try:
        created = api.create_code_review(plan.space.agent_space_id, plan.opts, plan.repos)
    except ClientError as exc:
        spinner.stop()
        fatal(f"CreateCodeReview 실패: {exc.response.get('Error', {}).get('Message', exc)}")
    except BotoCoreError as exc:
        spinner.stop()
        fatal(f"CreateCodeReview 실패: {exc}")
    finally:
        spinner.stop()

    code_review_id = created.get("codeReviewId", "")
    print(f"{C.OK}✓ Code Review 생성 완료{C.RESET}")
    print(f"  {C.LABEL}codeReviewId{C.RESET}  {code_review_id}")
    print(f"  {C.LABEL}title{C.RESET}         {created.get('title', plan.opts.title)}")
    print(f"  {C.LABEL}repositories{C.RESET}  "
          f"{len(((created.get('assets') or {}).get('integratedRepositories') or []))}개")

    if args.no_start:
        print()
        print("실행 명령:")
        print(f"  aws securityagent start-code-review-job --region {api.region} \\")
        print(f"    --agent-space-id {plan.space.agent_space_id} \\")
        print(f"    --code-review-id {code_review_id}")
        return 0

    should_start = args.start or ask_yes_no("\n지금 Code Review Job 을 실행할까요?", default=True)
    if not should_start:
        print()
        print("나중에 실행하려면:")
        print(f"  aws securityagent start-code-review-job --region {api.region} \\")
        print(f"    --agent-space-id {plan.space.agent_space_id} \\")
        print(f"    --code-review-id {code_review_id}")
        return 0

    spinner.start("StartCodeReviewJob 호출 중…")
    try:
        job = api.start_code_review_job(plan.space.agent_space_id, code_review_id)
    except ClientError as exc:
        spinner.stop()
        fatal(f"StartCodeReviewJob 실패: {exc.response.get('Error', {}).get('Message', exc)}")
    except BotoCoreError as exc:
        spinner.stop()
        fatal(f"StartCodeReviewJob 실패: {exc}")
    finally:
        spinner.stop()

    job_id = job.get("codeReviewJobId", "")
    print(f"{C.OK}✓ Job 실행 시작{C.RESET}")
    print(f"  {C.LABEL}codeReviewJobId{C.RESET}  {job_id}")
    print(f"  {C.LABEL}status{C.RESET}           "
          f"{status_color(job.get('status', ''))}{job.get('status', '-')}{C.RESET}")

    if args.no_watch or not job_id:
        return 0

    final = watch_job(api, plan.space.agent_space_id, job_id, args.poll_seconds)
    print()
    if final == "COMPLETED":
        print(f"{C.OK}✓ Job 완료 (COMPLETED){C.RESET}")
        print(f"  Findings: aws securityagent list-findings --region {api.region} "
              f"--agent-space-id {plan.space.agent_space_id}")
        return 0
    if final in ("FAILED", "STOPPED"):
        print(f"{C.ERR}Job 종료: {final}{C.RESET}")
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\n중단했습니다.\n")
        raise SystemExit(130)
