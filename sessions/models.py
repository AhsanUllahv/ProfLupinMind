from datetime import datetime, timezone

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Base(DeclarativeBase):
    pass


class PentestSession(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    target: Mapped[str] = mapped_column(String(255), default="")
    scope_json: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(32), default="active")
    context_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[str] = mapped_column(String(40), default=utc_now)
    updated_at: Mapped[str] = mapped_column(String(40), default=utc_now)

    commands: Mapped[list["CommandRecord"]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="CommandRecord.id",
    )
    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="FindingRecord.id",
    )


class CommandRecord(Base):
    __tablename__ = "commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    command: Mapped[str] = mapped_column(Text)
    tool: Mapped[str] = mapped_column(String(100), default="")
    target: Mapped[str] = mapped_column(String(255), default="")
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration: Mapped[float | None] = mapped_column(Float, nullable=True)
    timed_out: Mapped[bool] = mapped_column(Boolean, default=False)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    dangerous: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(Text, default="")
    output_excerpt: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[str] = mapped_column(String(40), default=utc_now)

    session: Mapped[PentestSession] = relationship(back_populates="commands")


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    tool: Mapped[str] = mapped_column(String(100), default="")
    type: Mapped[str] = mapped_column(String(100), default="")
    detail: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default="INFO")
    created_at: Mapped[str] = mapped_column(String(40), default=utc_now)

    session: Mapped[PentestSession] = relationship(back_populates="findings")
