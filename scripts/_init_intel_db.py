import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from sqlalchemy import text

from backend.database.db import get_engine, init_db, reset_engine_for_tests

reset_engine_for_tests()
init_db()
with get_engine().connect() as conn:
    rows = conn.execute(
        text("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1")
    ).fetchall()
    print("tables:", [r[0] for r in rows])
print("schema OK")
