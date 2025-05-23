"""Add CrewAcknowledgement Table

Revision ID: 51d41f211490
Revises: 9cce8d02f87a
Create Date: 2025-04-10 21:08:06.279535

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '51d41f211490'
down_revision = '9cce8d02f87a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('crew_acknowledgement', schema=None) as batch_op:
        batch_op.alter_column('id',
               existing_type=mysql.INTEGER(),
               type_=mysql.BIGINT(unsigned=True),
               existing_nullable=False,
               autoincrement=True)
        batch_op.create_foreign_key(None, 'user', ['crew_member_id'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('crew_acknowledgement', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.alter_column('id',
               existing_type=mysql.BIGINT(unsigned=True),
               type_=mysql.INTEGER(),
               existing_nullable=False,
               autoincrement=True)

    # ### end Alembic commands ###
