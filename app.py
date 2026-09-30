from flask import Flask, request
from datetime import datetime, timedelta
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "login_logs.txt")

users = {
    "alice": "Welcome123",
    "bob": "Welcome123",
    "charlie": "Welcome123",
    "david": "Python123"
}

# Security settings
TIME_WINDOW = 5
USER_THRESHOLD = 3

blocked_ips = {}


def get_failed_users(ip_address):
    """Return unique users with recent failed logins from an IP."""

    failed_users = set()
    current_time = datetime.now()

    try:
        with open("login_logs.txt", "r", encoding="utf-8") as file:

            for line in file:
                parts = line.strip().split(" | ")

                if len(parts) != 4:
                    continue

                timestamp_text = parts[0]
                log_ip = parts[1].replace("IP: ", "")
                username = parts[2].replace("User: ", "")
                result = parts[3].replace("Result: ", "")

                if log_ip != ip_address:
                    continue

                if result != "Invalid username or password":
                    continue

                timestamp = datetime.strptime(
                    timestamp_text,
                    "%Y-%m-%d %H:%M:%S"
                )

                if current_time - timestamp <= timedelta(minutes=TIME_WINDOW):
                    failed_users.add(username)

    except FileNotFoundError:
        pass

    return failed_users


@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        ip_address = request.remote_addr
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Check whether IP is already blocked
        if ip_address in blocked_ips:

            if datetime.now() < blocked_ips[ip_address]:
                return "Access temporarily blocked due to suspicious activity."

            del blocked_ips[ip_address]

        if username in users and users[username] == password:

            result = "Login successful"

        else:

            result = "Invalid username or password"

        # Write security log
        with open(LOG_FILE, "a", encoding="utf-8") as file:
             file.write(
                 f"{timestamp} | IP: {ip_address} | "
                 f"User: {username} | Result: {result}\n"
        )

        # Check for password spraying pattern
        if result == "Invalid username or password":

            failed_users = get_failed_users(ip_address)

            if len(failed_users) >= USER_THRESHOLD:

                blocked_ips[ip_address] = (
                    datetime.now() + timedelta(minutes=5)
                )

                return (
                    "SECURITY ALERT: Suspicious login activity detected. "
                    "Access temporarily blocked."
                )

        return result

    return """
    <!DOCTYPE html>
    <html>

    <head>
        <title>Cybersecurity Lab</title>
    </head>

    <body>

        <h2>Cybersecurity Lab Login</h2>

        <form method="POST">

            <label>Username:</label><br>
            <input type="text" name="username" required>

            <br><br>

            <label>Password:</label><br>
            <input type="password" name="password" required>

            <br><br>

            <input type="submit" value="Login">

        </form>

    </body>

    </html>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)