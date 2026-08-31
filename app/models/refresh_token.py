import uuid
from datetime import datetime
from app.core.time import utc_now
from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    # Unique refresh-token record ID
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # User who owns the token
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # SHA-256 hash of the refresh token
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    # Token expiration time
    expires_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )

    # Whether token has been revoked
    revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # Creation time
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=utc_now,
        nullable=False,
    )

    # Revocation time
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )
