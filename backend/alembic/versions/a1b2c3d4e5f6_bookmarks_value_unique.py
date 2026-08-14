"""bookmarks.value kolonuna unique kisitlama ekle

`create_bookmark` uc noktasi ayni gostergenin iki kez eklenmesini `IntegrityError`
yakalayip 409 donerek engellemeyi amacliyordu, ama ilk migration (451eeffa37c5)
indeksi unique=False olusturmustu — bu kisitlama hic var olmadigi icin ayni IOC
sessizce birden fazla kez eklenebiliyordu.

Revision ID: a1b2c3d4e5f6
Revises: 451eeffa37c5
Create Date: 2026-08-14 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "451eeffa37c5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index(op.f("ix_bookmarks_value"), table_name="bookmarks")
    op.create_index(op.f("ix_bookmarks_value"), "bookmarks", ["value"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_bookmarks_value"), table_name="bookmarks")
    op.create_index(op.f("ix_bookmarks_value"), "bookmarks", ["value"], unique=False)
