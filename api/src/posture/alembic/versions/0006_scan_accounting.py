"""scan accounting: images inventoried / rescanned / skipped fresh / targeted, inventory and posture
hashes (post-scan stage scoping: provenance, controls engine, auto-reports)

Revision ID: 0006_scan_accounting
Revises: 0005_control_status_detail
Create Date: 2026-10-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_scan_accounting"
down_revision = "0005_control_status_detail"
branch_labels = None
depends_on = None

COUNTS = ("images_inventoried", "images_rescanned", "images_skipped_fresh", "images_targeted")
HASHES = ("inventory_hash", "posture_hash")


def upgrade() -> None:
    for name in COUNTS:
        op.add_column("scans", sa.Column(name, sa.Integer(), nullable=True))
    for name in HASHES:
        op.add_column("scans", sa.Column(name, sa.String(length=64), nullable=True))


def downgrade() -> None:
    for name in (*HASHES, *COUNTS):
        op.drop_column("scans", name)
