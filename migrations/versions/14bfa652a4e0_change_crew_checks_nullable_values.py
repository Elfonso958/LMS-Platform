"""Change crew checks nullable values

Revision ID: 14bfa652a4e0
Revises: 4a72ca5408a9
Create Date: 2025-04-05 22:06:57.965214

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '14bfa652a4e0'
down_revision = '4a72ca5408a9'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('crew_check_meta', schema=None) as batch_op:
        batch_op.alter_column('flight_time_day',
               existing_type=mysql.BIGINT(unsigned=True),
               nullable=True,
               existing_server_default=sa.text("'0'"))
        batch_op.alter_column('flight_time_night',
               existing_type=mysql.BIGINT(unsigned=True),
               nullable=True,
               existing_server_default=sa.text("'0'"))
        batch_op.alter_column('flight_time_if',
               existing_type=mysql.BIGINT(unsigned=True),
               nullable=True,
               existing_server_default=sa.text("'0'"))
        batch_op.alter_column('current_check_due',
               existing_type=sa.DATE(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('crew_check_meta', schema=None) as batch_op:
        batch_op.alter_column('current_check_due',
               existing_type=sa.DATE(),
               nullable=False)
        batch_op.alter_column('flight_time_if',
               existing_type=mysql.BIGINT(unsigned=True),
               nullable=False,
               existing_server_default=sa.text("'0'"))
        batch_op.alter_column('flight_time_night',
               existing_type=mysql.BIGINT(unsigned=True),
               nullable=False,
               existing_server_default=sa.text("'0'"))
        batch_op.alter_column('flight_time_day',
               existing_type=mysql.BIGINT(unsigned=True),
               nullable=False,
               existing_server_default=sa.text("'0'"))

    # ### end Alembic commands ###
