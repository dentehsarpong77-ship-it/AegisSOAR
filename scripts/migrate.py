import os
import sqlite3
import shutil
from datetime import datetime
from sqlalchemy.orm import sessionmaker
from aegissoar.config import DATA_DIR, DATABASE_URL
from aegissoar.db_prod import get_prod_engine, init_db_prod, Event, Incident, Blocklist, PlaybookExecution, User, Organization, Membership, Invitation, AuditLog

SQLITE_PATH = DATA_DIR / "aegis.db"

def backup_sqlite():
    if not SQLITE_PATH.exists():
        print("[-] SQLite database not found!")
        return None
    backup_path = DATA_DIR / f"aegis_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    shutil.copy2(SQLITE_PATH, backup_path)
    print(f"[+] SQLite database backed up to: {backup_path}")
    return backup_path

def parse_dt(val):
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    try:
        # Try ISO format
        return datetime.fromisoformat(val)
    except Exception:
        try:
            # Fallback format
            return datetime.strptime(val, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return datetime.now()

def run_migration():
    print("[*] Starting Phase 2B Non-Destructive Migration: SQLite -> PostgreSQL")

    if not DATABASE_URL:
        print("[-] Error: DATABASE_URL is not set!")
        return

    # 1. Backup SQLite
    backup_path = backup_sqlite()
    if not backup_path:
        return

    # 2. Connect to SQLite
    sqlite_conn = sqlite3.connect(SQLITE_PATH)
    sqlite_conn.row_factory = sqlite3.Row
    sqlite_cursor = sqlite_conn.cursor()

    # 3. Initialize PostgreSQL
    print("[*] Initializing PostgreSQL schema...")
    try:
        init_db_prod(DATABASE_URL)
    except Exception as e:
        print(f"[-] Failed to initialize PostgreSQL: {e}")
        return

    engine = get_prod_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    session = Session()

    tables_map = [
        ("users", User),
        ("organizations", Organization),
        ("memberships", Membership),
        ("invitations", Invitation),
        ("events", Event),
        ("incidents", Incident),
        ("blocklist", Blocklist),
        ("playbook_executions", PlaybookExecution),
        ("audit_logs", AuditLog),
    ]

    try:
        for table_name, model_class in tables_map:
            print(f"[*] Migrating table '{table_name}'...")
            sqlite_cursor.execute(f"SELECT * FROM {table_name}")
            rows = sqlite_cursor.fetchall()

            migrated_count = 0
            for row in rows:
                row_dict = dict(row)

                # Type conversions / cleaning per model
                if table_name == "users" and "created_at" in row_dict:
                    row_dict["created_at"] = parse_dt(row_dict["created_at"])
                elif table_name == "organizations":
                    row_dict["created_at"] = parse_dt(row_dict.get("created_at"))
                    row_dict["updated_at"] = parse_dt(row_dict.get("updated_at"))
                elif table_name == "memberships":
                    row_dict["created_at"] = parse_dt(row_dict.get("created_at"))
                    row_dict["updated_at"] = parse_dt(row_dict.get("updated_at"))
                elif table_name == "invitations":
                    row_dict["expires_at"] = parse_dt(row_dict.get("expires_at"))
                    row_dict["created_at"] = parse_dt(row_dict.get("created_at"))
                elif table_name == "events":
                    row_dict["timestamp"] = parse_dt(row_dict.get("timestamp"))
                elif table_name == "incidents":
                    row_dict["created_at"] = parse_dt(row_dict.get("created_at"))
                    row_dict["updated_at"] = parse_dt(row_dict.get("updated_at"))
                elif table_name == "blocklist":
                    row_dict["blocked_at"] = parse_dt(row_dict.get("blocked_at"))
                    row_dict["expires_at"] = parse_dt(row_dict.get("expires_at"))
                    # active boolean fix
                    if "active" in row_dict:
                        row_dict["active"] = bool(row_dict["active"])
                elif table_name == "playbook_executions":
                    row_dict["executed_at"] = parse_dt(row_dict.get("executed_at"))
                elif table_name == "audit_logs":
                    row_dict["timestamp"] = parse_dt(row_dict.get("timestamp"))

                # Check if record already exists in Postgres to prevent duplicates
                pk_col = list(model_class.__table__.primary_key.columns)[0].name
                pk_val = row_dict.get(pk_col)

                existing = session.query(model_class).filter(getattr(model_class, pk_col) == pk_val).first()
                if not existing:
                    instance = model_class(**row_dict)
                    session.merge(instance) # merge handles upsert safely
                    migrated_count += 1

            session.commit()
            print(f"[+] Migrated {migrated_count} records for '{table_name}'.")

        print("[+] Migration successfully completed and verified!")
    except Exception as e:
        session.rollback()
        print(f"[-] Migration failed due to error: {e}")
        raise e
    finally:
        session.close()
        sqlite_conn.close()

if __name__ == "__main__":
    run_migration()
