import json
import uuid
from dataclasses import asdict
from typing import Iterable

from core.context import Finding, SessionContext
from core.executor import ExecutionResult
from sessions.db import create_session_factory
from sessions.models import CommandRecord, FindingRecord, PentestSession, utc_now


class SessionManager:
    def __init__(self, db_path: str = "sessions/proflupinmind.sqlite3"):
        self.SessionLocal = create_session_factory(db_path)

    def create_session(self, target: str, scope: Iterable[str]) -> str:
        session_id = uuid.uuid4().hex[:12]
        context = SessionContext(target=target, scope=list(scope))
        with self.SessionLocal() as db:
            db.add(
                PentestSession(
                    id=session_id,
                    target=target,
                    scope_json=json.dumps(list(scope)),
                    context_json=self._context_to_json(context),
                )
            )
            db.commit()
        return session_id

    def load_context(self, session_id: str) -> SessionContext:
        with self.SessionLocal() as db:
            row = db.get(PentestSession, session_id)
            if row is None:
                raise ValueError(f"Session not found: {session_id}")
            context = self._context_from_json(row.context_json)
            context.target = context.target or row.target
            context.scope = context.scope or json.loads(row.scope_json or "[]")
            return context

    def list_sessions(self) -> list[dict]:
        with self.SessionLocal() as db:
            rows = (
                db.query(PentestSession)
                .order_by(PentestSession.updated_at.desc())
                .all()
            )
            return [
                {
                    "id": row.id,
                    "target": row.target,
                    "status": row.status,
                    "created_at": row.created_at,
                    "updated_at": row.updated_at,
                    "commands": len(row.commands),
                    "findings": len(row.findings),
                }
                for row in rows
            ]

    def save_context(self, session_id: str, context: SessionContext):
        with self.SessionLocal() as db:
            row = db.get(PentestSession, session_id)
            if row is None:
                return
            row.target = context.target
            row.scope_json = json.dumps(context.scope)
            row.context_json = self._context_to_json(context)
            row.updated_at = utc_now()
            db.commit()

    def mark_active(self, session_id: str):
        with self.SessionLocal() as db:
            row = db.get(PentestSession, session_id)
            if row:
                row.status = "active"
                row.updated_at = utc_now()
                db.commit()

    def record_command(
        self,
        session_id: str,
        context: SessionContext,
        command: str,
        tool: str,
        result: ExecutionResult | None = None,
        blocked: bool = False,
        dangerous: bool = False,
        reason: str = "",
    ):
        output = result.output if result else ""
        with self.SessionLocal() as db:
            db.add(
                CommandRecord(
                    session_id=session_id,
                    command=command,
                    tool=tool,
                    target=context.target,
                    exit_code=result.exit_code if result else None,
                    duration=result.duration if result else None,
                    timed_out=result.timed_out if result else False,
                    blocked=blocked,
                    dangerous=dangerous,
                    reason=reason,
                    output_excerpt=output[:4000],
                )
            )
            row = db.get(PentestSession, session_id)
            if row:
                row.updated_at = utc_now()
            db.commit()

    def sync_findings(self, session_id: str, findings: list[Finding]):
        with self.SessionLocal() as db:
            existing = {
                (row.tool, row.type, row.detail)
                for row in db.query(FindingRecord).filter_by(session_id=session_id).all()
            }
            for finding in findings:
                key = (finding.tool, finding.type, finding.detail)
                if key in existing:
                    continue
                db.add(
                    FindingRecord(
                        session_id=session_id,
                        tool=finding.tool,
                        type=finding.type,
                        detail=finding.detail,
                        severity=finding.severity,
                        created_at=finding.timestamp,
                    )
                )
            row = db.get(PentestSession, session_id)
            if row:
                row.updated_at = utc_now()
            db.commit()

    def close_session(self, session_id: str, context: SessionContext):
        with self.SessionLocal() as db:
            row = db.get(PentestSession, session_id)
            if row:
                row.status = "closed"
                row.context_json = self._context_to_json(context)
                row.updated_at = utc_now()
                db.commit()

    def delete_session(self, session_id: str) -> bool:
        with self.SessionLocal() as db:
            row = db.get(PentestSession, session_id)
            if row is None:
                return False
            db.delete(row)
            db.commit()
            return True

    def _context_to_json(self, context: SessionContext) -> str:
        data = asdict(context)
        return json.dumps(data)

    def save_scan_meta(self, session_id: str, meta: dict) -> None:
        """Store scan-level metadata (chains, attack surface, tool summaries) inside context_json."""
        with self.SessionLocal() as db:
            row = db.get(PentestSession, session_id)
            if row is None:
                return
            try:
                existing = json.loads(row.context_json or "{}")
            except Exception:
                existing = {}
            existing["_scan_meta"] = meta
            row.context_json = json.dumps(existing, ensure_ascii=False)
            row.updated_at = utc_now()
            db.commit()

    def _context_from_json(self, raw: str) -> SessionContext:
        if not raw:
            return SessionContext()
        data = json.loads(raw)
        findings = [Finding(**item) for item in data.pop("findings", [])]
        data.pop("_scan_meta", None)  # stored alongside context, not part of SessionContext
        context = SessionContext(**data)
        context.findings = findings
        return context
