"""Small example showing safer patterns for the first analyzer version."""

import os
import subprocess

API_KEY = os.getenv("API_KEY")
subprocess.run(["python", "--version"], shell=False, check=True)
cursor.execute("SELECT * FROM users WHERE name = ?", (username,))

try:
    process_data()
except ValueError as error:
    print(f"Invalid input: {error}")
