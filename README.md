# Password Spraying Attack Detection System

## 1. Introduction

Password spraying is a type of credential attack where an attacker
attempts a small number of commonly used passwords against multiple
user accounts.

This project demonstrates how suspicious login activity can be detected
and blocked in a controlled local cybersecurity laboratory.

## 2. Objective

The objectives of this project are:

- Create a local login application.
- Record authentication attempts.
- Record timestamp, IP address, username and result.
- Detect multiple failed logins against different users.
- Detect activity within a defined time window.
- Temporarily block suspicious activity.

## 3. Technologies Used

- Python
- Flask
- VS Code
- HTML
- File-based logging

## 4. System Architecture

User
  |
  v
Login Application
  |
  v
Authentication
  |
  v
Security Log
  |
  v
Password Spraying Detector
  |
  v
Security Alert / Temporary Block

## 5. Detection Logic

The system checks:

1. Failed authentication attempts.
2. Source IP address.
3. Different usernames targeted.
4. Activity within five minutes.

If three or more different users have recent failed
authentication attempts from the same IP address,
the system reports possible password spraying.

## 6. Protection

When suspicious activity is detected, the local application
temporarily blocks the source IP for five minutes.

## 7. Testing

The project was tested using dummy accounts:

- alice
- bob
- charlie
- david

All testing was performed against the local application.

## 8. Result

The system successfully:

- Recorded login attempts.
- Identified suspicious multi-user failures.
- Generated a security warning.
- Temporarily blocked suspicious activity.

## 9. Ethical Considerations

This project is designed for cybersecurity education and
authorized laboratory testing only.

No real user accounts, third-party websites or unauthorized
systems were targeted.

## 10. Conclusion

The project demonstrates a basic method for detecting password
spraying behavior using authentication logs, IP addresses,
usernames and a time-based detection threshold.