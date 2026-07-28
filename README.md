# Cloud Security Monitoring Dashboard

A lightweight cloud-based security monitoring dashboard built using **Python, Flask, Scapy, SQLite, and AWS EC2**. The project captures ICMP network traffic in real time, stores packet information in a database, and displays it through a web dashboard for monitoring and analysis.

This project demonstrates the fundamentals of cloud security monitoring and how a Security Operations Center (SOC) can collect, log, and visualize network events within an AWS environment.

---

## Features

- User login authentication
- Real-time ICMP packet monitoring
- Live security dashboard
- Displays Source IP, Destination IP, Protocol, Packet Size and Timestamp
- Stores monitoring logs using SQLite
- Hosted on AWS EC2
- Simple and lightweight Flask web application

---

# Project Workflow

```text
              Network Traffic
                     │
                     ▼
            monitor.py (Scapy)
                     │
         Captures ICMP Network Packets
                     │
                     ▼
              SQLite Database
                     │
                     ▼
             Flask Application
                     │
                     ▼
        Cloud Security Dashboard
```

---

# Technologies Used

- Python
- Flask
- Scapy
- SQLite
- HTML
- CSS
- JavaScript
- AWS EC2
- Git & GitHub

---

# Project Screenshots
<img width="1917" height="875" alt="Screenshot 2026-07-28 152522" src="https://github.com/user-attachments/assets/88dc446e-4f0a-4884-ba13-3c7607076b26" />
### Default Login Credentials

| Username | Password |
|----------|----------|
| admin | admin123 |

---

## Monitoring Dashboard
<img width="1916" height="871" alt="Screenshot 2026-07-28 152619" src="https://github.com/user-attachments/assets/a209aa2b-9460-4902-b32e-97711fcd72a4" />

<img width="1917" height="870" alt="Screenshot 2026-07-28 152731" src="https://github.com/user-attachments/assets/5d2a93ae-3800-4d34-ada4-58f0460b958e" />


---

# Installation Guide

## 1. Install Git

Ubuntu

```bash
sudo apt update
sudo apt install git -y
```

Amazon Linux

```bash
sudo yum install git -y
```

Verify installation

```bash
git --version
```

---

## 2. Clone the Repository

```bash
git clone https://github.com/nihalpatel28/cloud-monitor.git
```

Move into the project directory

```bash
cd cloud-monitor
```

---

## 3. Create a Virtual Environment

```bash
python3 -m venv venv
```

Activate the virtual environment

Linux

```bash
source venv/bin/activate
```

---

## 4. Install Project Dependencies

```bash
pip install -r requirements.txt
```

---

## 5. Start the Flask Application

```bash
python3 app.py
```

Open another terminal and start the monitoring service

```bash
python3 monitor.py
```

---

# Access the Dashboard

```
http://<EC2-Public-IP>:5000
```

Example

```
http://52.xxx.xxx.xxx:5000
```

---

# Project Structure

```
cloud-monitor/
│
├── app.py
├── monitor.py
├── database.db
├── requirements.txt
├── static/
├── templates/
├── images/
├── logs/
└── README.md
```

---

# What This Project Demonstrates

- Cloud Security Monitoring
- Packet Sniffing using Scapy
- Flask Web Development
- SQLite Database Integration
- AWS EC2 Deployment
- Security Event Logging
- Basic SOC Dashboard Development

---

# Future Improvements

- SSH Login Monitoring
- Brute Force Detection
- IP Blocking
- Email Alerts
- Geo-location of IP Addresses
- User Role Management
- CloudWatch Integration
- Threat Intelligence Integration

---

# Author

**Nihal Patel**

GitHub: https://github.com/nihalpatel28
