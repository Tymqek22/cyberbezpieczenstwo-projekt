"""module 2: failed-login lockout, honeytoken account

Revision ID: b7c2e91d4a10
Revises: 432918634c55
Create Date: 2026-11-16 12:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b7c2e91d4a10'
down_revision: Union[str, Sequence[str], None] = '432918634c55'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default is required because the tables already contain rows
    op.add_column('users', sa.Column('failed_login_count', sa.Integer(), server_default='0', nullable=False))
    op.add_column('users', sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True))
    op.add_column('users', sa.Column('is_honeytoken', sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column('app_settings', sa.Column('max_failed_logins', sa.Integer(), server_default='5', nullable=False))


def downgrade() -> None:
    op.drop_column('app_settings', 'max_failed_logins')
    op.drop_column('users', 'is_honeytoken')
    op.drop_column('users', 'locked_until')
    op.drop_column('users', 'failed_login_count')
