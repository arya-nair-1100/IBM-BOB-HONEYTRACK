# HoneyTrack — Cowrie Honeypot Intelligence Platform

HoneyTrack is a real-time SSH honeypot monitoring and threat-response system built on top of [Cowrie](https://github.com/cowrie/cowrie). It parses Cowrie's JSON event logs, scores every attacker session using a multi-factor risk engine, enforces application-level firewall rules, and exposes all captured data through a live Flask web dashboard.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Directory Structure](#directory-structure)
- [Risk Scoring Model](#risk-scoring-model)
- [Prerequisites](#prerequisites)
- [Setup Instructions](#setup-instructions)
  - [1. System Preparation](#1-system-preparation)
  - [2. Install and Start Cowrie](#2-install-and-start-cowrie)
  - [3. Set Up HoneyTrack](#3-set-up-honeytrack)
  - [4. Initialise the Database](#4-initialise-the-database)
  - [5. Start the Log Parser](#5-start-the-log-parser)
  - [6. Launch the Dashboard](#6-launch-the-dashboard)
- [Firewall Modifications](#firewall-modifications)
- [Restarting Cowrie](#restarting-cowrie)
- [Database Schema](#database-schema)
- [Dashboard](#dashboard)

---

## Overview

When an attacker connects to the honeypot over SSH, Cowrie records every login attempt and every command typed. HoneyTrack continuously tails those logs and:

1. **Parses** each login and command event in real time.
2. **Scores** the session with a risk engine that weighs credentials, protocol, brute-force history, command categories, and behavioural escalation patterns.
3. **Enforces** an application-level firewall by logging block rules to SQLite and terminating active Cowrie sessions through a Unix domain socket.
4. **Alerts** administrators when a session crosses the MEDIUM, HIGH, or CRITICAL threshold.
5. **Visualises** all data — sessions, commands, firewall rules, and summary statistics — through a browser-based dashboard.

---

## Architecture

```
Attacker (SSH)
      │
      ▼
┌─────────────┐      cowrie.json log      ┌──────────────┐
│   Cowrie    │ ─────────────────────────▶│  parser.py   │
│  Honeypot   │◀── Unix socket (kill) ────│  (tail loop) │
└─────────────┘                           └──────┬───────┘
                                                 │
                              ┌──────────────────┼──────────────────┐
                              ▼                  ▼                  ▼
                       risk_engine.py    command_risk.py     firewall.py
                       (login scoring)  (command scoring)   (block rules)
                              │                  │                  │
                              └──────────────────┴──────────────────┘
                                                 │
                                                 ▼
                                       SQLite  honeytrack.db
                                   (sessions · commands · firewall_rules)
                                                 │
                                                 ▼
                                           app.py  (Flask)
                                                 │
                                                 ▼
                                      http://127.0.0.1:5000
```

---

## Directory Structure

```
Cowrie-Honeypot-main/
│
├── files/                        # Core application source files
│   ├── app.py                    # Flask web application (dashboard)
│   ├── parser.py                 # Real-time Cowrie log monitor and event processor
│   ├── risk_engine.py            # Multi-factor risk scoring engine (login events)
│   ├── command_risk.py           # Per-command risk scoring, categorisation, and sequence analysis
│   ├── firewall.py               # Application-level firewall: block rules and session termination
│   ├── alerts.py                 # Admin alert generator (writes to alerts.log)
│   ├── database.py               # Database initialisation script
│   ├── models.py                 # SQLite insert helpers
│   ├── update_session_risk.py    # Utility to recalculate session risk scores
│   └── requirements.txt          # Python package dependencies
│
├── templates/
│   └── dashboard.html            # Jinja2 template for the Flask dashboard
│
├── static/
│   └── css/
│       └── style.css             # Dashboard stylesheet
│
├── database/
│   └── database.txt              # Reference SQL dump of sample captured data
│
├── MODIF FIREWALL/               # Firewall integration — modified Cowrie source files
│   ├── firewallmodif.py          # Enhanced firewall module (production version)
│   ├── parser(final).py          # Final parser used with firewall modifications
│   ├── PRECAUTIONS.txt           # Notes on applying these modifications safely
│   └── cowrie/src/cowrie/ssh/
│       ├── factory.py            # Modified Cowrie SSH factory (session tracking)
│       └── transport.py          # Modified Cowrie SSH transport (socket control)
│
├── corrected code/
│   ├── parseer(corrected).py     # Corrected parser with deduplication fixes
│   └── style(corrected).css      # Corrected dashboard stylesheet
│
├── setups or commands u need/
│   ├── Terminal commands         # Full ordered setup guide (Steps 1–15)
│   ├── Restarting cowrie         # Commands to restart a stopped Cowrie instance
│   └── TERMINAL ALL EXECUTING COMMANDS REVIEWING STAGE
│
├── OUTPUT/
│   ├── Flask dashbaord preview   # Screenshot / preview of the dashboard
│   └── INSTRUCTIONS              # Notes on where to place the CSS file
│
└── General Stuffs/               # Supplementary screenshots and notes
```

---

## Risk Scoring Model

Each attacker session is assigned a score from **0 – 100** built from eight weighted components.

| Component | Factor | Max Points |
|-----------|--------|-----------|
| **U** – Username risk | Common usernames (`root`, `admin`, …) | 15 |
| **P** – Password risk | Weak / short passwords | 20 |
| **A** – Authentication result | Login success vs. failure | 20 |
| **B** – Brute-force rate | Number of login attempts | 30 |
| **N** – Protocol risk | SSH (10) vs. Telnet (15) | 15 |
| **H** – Attacker history | Previous sessions from same IP | 20 |
| **C** – Command behaviour | Accumulated command risk score | 25 |
| **E** – Behavioural escalation | Multi-category / repeat suspicious commands | 20 |

### Risk Levels and Firewall Actions

| Score Range | Level | Firewall Action |
|-------------|-------|-----------------|
| 0 – 29 | `LOW` | Monitor only |
| 30 – 59 | `MEDIUM` | Block (temporary) |
| 60 – 79 | `HIGH` | Alert + Block (temporary) |
| 80 – 100 | `CRITICAL` | Permanent Block |

### Command Risk Examples

| Command | Risk Score | Category |
|---------|-----------|----------|
| `ls`, `pwd` | 1 – 2 | Reconnaissance |
| `whoami`, `id` | 5 | Reconnaissance |
| `nmap`, `nc` | 35 | Network recon / tool |
| `wget`, `curl`, `scp` | 40 | Download / exfiltration |
| `rm -rf` | 50 | Destructive |
| `useradd`, `chpasswd` | 35 | Account / credential manipulation |

---

## Prerequisites

- **OS:** Kali Linux (recommended) or any Debian-based Linux distribution
- **Python:** 3.8 or later
- **Git**
- **Docker** (optional, for containerised deployments)
- **SQLite3**

---

## Setup Instructions

### 1. System Preparation

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install git sqlite3 -y
```

### 2. Install and Start Cowrie

```bash
# Clone Cowrie
cd ~
git clone https://github.com/cowrie/cowrie.git
cd cowrie

# Create and activate a virtual environment
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# Install Cowrie dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Copy the default configuration
cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Start Cowrie
bin/cowrie start

# Verify it is running
bin/cowrie status
```

Cowrie listens on port **2222** by default. You can verify with:

```bash
ss -tlnp | grep 2222
```

**Test the honeypot** by connecting from another terminal:

```bash
ssh root@127.0.0.1 -p 2222
# Username: root   Password: root
```

### 3. Set Up HoneyTrack

```bash
cd ~
git clone https://github.com/arya-nair-1100/Cowrie-Honeypot
cd Cowrie-Honeypot

# Install Flask (only dependency required at runtime)
pip install flask
```

### 4. Initialise the Database

```bash
# Create the database directory
mkdir -p database

# Initialise tables (sessions, commands, firewall_rules)
python files/database.py
```

Alternatively, open an SQLite shell and create the tables manually:

```bash
sqlite3 database/honeytrack.db
```

```sql
CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    timestamp     TEXT,
    src_ip        TEXT,
    protocol      TEXT,
    username      TEXT,
    password      TEXT,
    login_status  TEXT,
    risk_score    INTEGER,
    risk_level    TEXT,
    firewall_action TEXT
);

CREATE TABLE IF NOT EXISTS commands (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT,
    timestamp    TEXT,
    command      TEXT,
    command_risk INTEGER
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT,
    src_ip     TEXT,
    action     TEXT,
    reason     TEXT,
    status     TEXT,
    expires_at TEXT
);
```

### 5. Start the Log Parser

The parser tails Cowrie's JSON log file and processes every new event in real time.

> **Note:** Update the `LOGFILE` path at the top of `files/parser.py` to match your Cowrie installation path (default: `/home/<user>/cowrie/var/log/cowrie/cowrie.json`).

```bash
cd files
python parser.py
```

The parser will print live output for every login attempt, command, risk update, and firewall decision.

### 6. Launch the Dashboard

In a separate terminal:

```bash
cd files
python app.py
```

Open your browser and navigate to:

```
http://127.0.0.1:5000
```

The dashboard displays the 10 most recent sessions, the 10 most recent commands, active firewall rules, and four summary statistics: total sessions, total commands, high-risk sessions, and blocked IPs.

---

## Firewall Modifications

The `MODIF FIREWALL/` directory contains modified versions of two Cowrie internal files that enable session termination via a Unix domain socket (`/tmp/honeytrack_cowrie.sock`):

| File | Purpose |
|------|---------|
| `cowrie/src/cowrie/ssh/factory.py` | Tracks active sessions so they can be looked up by session ID |
| `cowrie/src/cowrie/ssh/transport.py` | Adds a socket listener that receives a session ID and closes the corresponding transport |

To apply the modifications, replace the corresponding files inside your Cowrie installation with the versions in this directory, then restart Cowrie.

> Read `MODIF FIREWALL/PRECAUTIONS.txt` before applying these changes.

---

## Restarting Cowrie

If Cowrie stops unexpectedly, use the following commands to bring it back up:

```bash
cd ~/cowrie
source cowrie-env/bin/activate

# Check current status
python -m cowrie.scripts.cowrie status

# Start if not running
python -m cowrie.scripts.cowrie start

# Confirm the SSH port is listening
ss -tlnp | grep 2222
```

---

## Database Schema

The SQLite database (`database/honeytrack.db`) holds three tables.

**`sessions`** — one row per attacker session

| Column | Type | Description |
|--------|------|-------------|
| `session_id` | TEXT | Cowrie session identifier (primary key) |
| `timestamp` | TEXT | ISO 8601 timestamp of the login event |
| `src_ip` | TEXT | Attacker source IP address |
| `protocol` | TEXT | `ssh` or `telnet` |
| `username` | TEXT | Credential used |
| `password` | TEXT | Credential used |
| `login_status` | TEXT | Cowrie event ID (`cowrie.login.success` / `…failed`) |
| `risk_score` | INTEGER | Accumulated risk score (0–100) |
| `risk_level` | TEXT | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `firewall_action` | TEXT | Last firewall decision applied |

**`commands`** — one row per command typed

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-incrementing primary key |
| `session_id` | TEXT | Foreign key → `sessions.session_id` |
| `timestamp` | TEXT | ISO 8601 timestamp |
| `command` | TEXT | Raw command string |
| `command_risk` | INTEGER | Risk score for this specific command |

**`firewall_rules`** — one row per block rule

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-incrementing primary key |
| `timestamp` | TEXT | When the rule was created |
| `src_ip` | TEXT | Blocked IP address |
| `action` | TEXT | `Block 1 min` / `Alert + Block 1 min` / `Permanent Block` |
| `reason` | TEXT | Human-readable reason string |
| `status` | TEXT | `ACTIVE` or `EXPIRED` |
| `expires_at` | TEXT | Expiry timestamp, or `NULL` for permanent blocks |

---

## Dashboard

The Flask dashboard (`app.py` + `templates/dashboard.html`) provides a single-page view of:

- **Summary cards** — total sessions, total commands, high-risk session count, blocked IP count
- **Recent Sessions table** — last 10 sessions with IP, credentials, risk score, level, and firewall action
- **Recent Commands table** — last 10 commands with session ID, timestamp, command text, and per-command risk score
- **Active Firewall Rules table** — last 10 rules with IP, action, reason, status, and expiry

The stylesheet is located at [`static/css/style.css`](static/css/style.css).
