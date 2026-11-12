import os
import shutil
import sqlite3
import argparse
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from aegissoar.config import DB_PATH, DATABASE_URL
from aegissoar.db_prod import Base, Event, Incident, Blocklist, PlaybookExecution, User, Organization, Membership, Invitation

def backup_sqlite():
    if os.path.exists(DB_PATH):
        backup_path = f"{DB_PATH}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copy2(DB_PATH, backup_path)
        print(f"Backed up SQLite database to {backup_path}")
        return backup_path
    else:
        print("SQLite database not found at", DB_PATH)
        return None

def migrate(dry_run=False, target_url=None):
    db_url = target_url or DATABASE_URL
    if not db_url:
        print("Error: DATABASE_URL is not set.")
        return

    print(f"Connecting to target PostgreSQL: {db_url}")
    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)

    if not dry_run:
        Base.metadata.create_all(bind=engine)

    sqlite_conn = sqlite3.connect(DB_PATH)
    sqlite_conn.row_factory = sqlite3.Row
    sqlite_cursor = sqlite_conn.cursor()

    tables = [
        ("users", User),
        ("organizations", Organization),
        ("memberships", Membership),
        ("invitations", Invitation),
        ("events", Event),
        ("incidents", Incident),
        ("blocklist", Blocklist),
        ("playbook_executions", PlaybookExecution)
    ]

    session = Session()
    try:
        for table_name, model_class in tables:
            sqlite_cursor.execute(f"SELECT * FROM {table_name}")
            rows = sqlite_cursor.fetchall()
            print(f"Found {len(rows)} records in SQLite table '{table_name}'")

            if dry_run:
                continue

            count = 0
            for row in rows:
                row_dict = dict(row)

                # Parse ISO date strings to datetime objects if needed for SQLAlchemy
                for key, val in row_dict.items():
                    if isinstance(val, str) and ('-T' in val or ('-' in val and ':' in val and len(val) >= 19)):
                        try:
                            row_dict[key] = datetime.fromisoformat(val.replace('Z', '+00:00'))
                        except ValueError:
                            pass
                    # Handle integer to boolean for blocklist.active
                    if table_name == 'blocklist' and key == 'active':
                        row_dict[key] = bool(val)

                # Check if already exists
                pk_col = list(model_class.__table__.primary_key.columns)[0].name
                pk_val = row_dict.get(pk_col)
                existing = session.query(model_class).filter(getattr(model_class, pk_col) == pk_val).first()

                if not existing:
                    obj = model_class(**row_dict)
                    session.add(obj)
                    count += 1

            session.commit()
            print(f"Migrated {count} new records into PostgreSQL table '{table_name}'")

        if not dry_run:
            print("Migration completed successfully!")
    except Exception as e:
        session.rollback()
        print(f"Migration failed: {e}")
        raise
    finally:
        session.close()
        sqlite_conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate SQLite to PostgreSQL")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run without writing to PostgreSQL")
    parser.add_argument("--url", type=str, help="Target PostgreSQL URL", default=None)
    args = parser.parse_args()

    print("Starting SQLite backup...")
    backup_sqlite()
    migrate(dry_run=args.dry_run, target_url=args.url)
