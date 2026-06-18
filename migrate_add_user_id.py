"""One-time migration: add user_id column to scan table, assign existing scans to user 1."""
import sqlite3

DB_PATH = "hisn.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# 1. Add the column (if it doesn't already exist)
try:
    cursor.execute("ALTER TABLE scan ADD COLUMN user_id INTEGER REFERENCES user(id)")
    print("✓ Added user_id column to scan table")
except sqlite3.OperationalError as e:
    if "duplicate column" in str(e).lower():
        print("→ Column user_id already exists, skipping ALTER")
    else:
        raise

# 2. Assign all NULL user_id scans to user 1
cursor.execute("UPDATE scan SET user_id = 1 WHERE user_id IS NULL")
updated = cursor.rowcount
print(f"✓ Assigned {updated} existing scans to user_id=1")

# 3. Quick sanity check
cursor.execute("SELECT user_id, COUNT(*) FROM scan GROUP BY user_id")
rows = cursor.fetchall()
print(f"→ Scans per user: {rows}")

conn.commit()
conn.close()
print("\nDone.")