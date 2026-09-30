from collections import defaultdict
from datetime import datetime

LOG_FILE = "login_logs.txt"

failed_attempts = defaultdict(list)

with open(LOG_FILE, "r", encoding="utf-8") as file:

    for line in file:
        line = line.strip()

        if "Invalid username or password" not in line:
            continue

        parts = line.split(" | ")

        if len(parts) != 4:
            continue

        timestamp_text = parts[0]
        ip_address = parts[1].replace("IP: ", "")
        username = parts[2].replace("User: ", "")

        timestamp = datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S"
        )

        failed_attempts[ip_address].append(
            (timestamp, username)
        )


print("\n=== Password Spraying Detection ===\n")

detected = False

for ip_address, attempts in failed_attempts.items():

    unique_users = set()

    for timestamp, username in attempts:
        unique_users.add(username)

    if len(unique_users) >= 3:

        detected = True

        print("WARNING: Possible password spraying detected!")
        print(f"Source IP: {ip_address}")
        print(f"Different users targeted: {len(unique_users)}")
        print("Users:")

        for username in unique_users:
            print(f"- {username}")

        print()


if not detected:
    print("No password spraying pattern detected.")