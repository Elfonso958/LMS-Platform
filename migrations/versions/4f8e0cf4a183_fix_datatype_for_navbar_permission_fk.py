"""Fix datatype for navbar permission FK

Revision ID: 4f8e0cf4a183
Revises: 14bfa652a4e0
Create Date: 2025-04-08 05:35:23.880150

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql


# revision identifiers, used by Alembic.
revision = '4f8e0cf4a183'
down_revision = '14bfa652a4e0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('nav_item_permission',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nav_item_id', sa.Integer(), nullable=False),
    sa.Column('role_id', sa.BigInteger().with_variant(mysql.BIGINT(unsigned=True), 'mysql'), nullable=False),
    sa.ForeignKeyConstraint(['nav_item_id'], ['nav_item.id'], ),
    sa.ForeignKeyConstraint(['role_id'], ['role_type.roleID'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('nav_item_permission')
    # ### end Alembic commands ###
