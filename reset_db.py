# reset_db.py - Simple version
import sqlite3
import os

# Delete the database file
db_file = 'instance/trackademia.db'
if os.path.exists(db_file):
    os.remove(db_file)
    print(f"Deleted database file: {db_file}")
else:
    print(f"Database file not found: {db_file}")

# Now just run the app to recreate everything
print("Database reset. Run 'python app.py' to recreate the database with new schema.")