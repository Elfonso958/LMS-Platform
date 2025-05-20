from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

revision = 'b9c4e1458af3'
down_revision = 'cee8665bb628'
# …

def upgrade():
    # ——— 1) Alter the column type to BIGINT UNSIGNED ———
    op.alter_column(
        'hr_task_template',
        'responsible_job_title_id',
        existing_type=sa.Integer(),
        type_=mysql.BIGINT(unsigned=True),
        existing_nullable=True,
    )

    # ——— 2) Create the foreign key constraint ———
    op.create_foreign_key(
        'hr_task_template_ibfk_2',
        'hr_task_template', 'job_title',
        ['responsible_job_title_id'], ['id']
    )

    # ——— (your other changes, e.g. email nullable) ———
    op.alter_column('user', 'email',
        existing_type=sa.String(length=150),
        nullable=True,
    )


def downgrade():
    # Drop the FK
    op.drop_constraint('hr_task_template_ibfk_2', 'hr_task_template', type_='foreignkey')

    # Revert the column type back to plain INTEGER
    op.alter_column(
        'hr_task_template',
        'responsible_job_title_id',
        existing_type=mysql.BIGINT(unsigned=True),
        type_=sa.Integer(),
        existing_nullable=True,
    )

    # Revert email if needed
    op.alter_column('user', 'email',
        existing_type=sa.String(length=150),
        nullable=False,
    )
