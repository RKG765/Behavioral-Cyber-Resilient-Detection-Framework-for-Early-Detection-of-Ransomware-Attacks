import sqlite3
import os

db_path = r"d:\project4\whitelist.db"
out_path = r"d:\project4\whitelist_data.txt"

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

lines = []
lines.append("=" * 80)
lines.append("WHITELIST DATABASE DUMP (whitelist.db)")
lines.append("=" * 80)

# Check tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = [row[0] for row in cursor.fetchall()]
lines.append(f"Tables in Database: {', '.join(tables)}\n")

for table in tables:
    lines.append("-" * 80)
    lines.append(f"TABLE: {table}")
    lines.append("-" * 80)
    
    cursor.execute(f"PRAGMA table_info({table});")
    col_info = cursor.fetchall()
    col_names = [c[1] for c in col_info]
    lines.append(f"Columns: {', '.join(col_names)}")
    
    cursor.execute(f"SELECT COUNT(*) FROM {table};")
    total_rows = cursor.fetchone()[0]
    lines.append(f"Total Records: {total_rows}\n")
    
    cursor.execute(f"SELECT * FROM {table};")
    rows = cursor.fetchall()
    
    # Format rows nicely
    lines.append(f"{'#':<4} | " + " | ".join(f"{c:<35}" for c in col_names))
    lines.append("-" * 80)
    for idx, r in enumerate(rows, 1):
        formatted_row = " | ".join(f"{str(val):<35}" for val in r)
        lines.append(f"{idx:<4} | {formatted_row}")
    lines.append("\n")

conn.close()

output_content = "\n".join(lines)
with open(out_path, "w", encoding="utf-8") as f:
    f.write(output_content)

print(f"Exported successfully to {out_path} ({len(output_content)} bytes)")
