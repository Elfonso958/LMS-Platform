# revision identifiers, used by Alembic.
revision = 'c68b37def332'
down_revision = '9922788cd0bd'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

def upgrade():
    with op.batch_alter_table('hr_task_template', schema=None) as batch_op:
        batch_op.create_foreign_key(None, 'job_title', ['responsible_job_title_id'], ['id'])

def downgrade():
    with op.batch_alter_table('hr_task_template', schema=None) as batch_op:
        batch_op.drop_constraint('fk_hrtasktemplate_responsible_job_title', type_='foreignkey')
        batch_op.drop_column('responsible_job_title_id')
