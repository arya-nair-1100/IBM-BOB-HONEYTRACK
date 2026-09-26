
import sqlite3
import socket
from datetime import datetime, timedelta

DATABASE = "database/honeytrack.db"

# Presentation setting: temporary blocks last 1 minute.
# Change to 30 later when you are ready.
BLOCK_DURATION_MINUTES = 1

COWRIE_SOCKET = "/tmp/honeytrack_cowrie.sock"


# ================= RISK DECISIONS =================

def get_firewall_action(risk_score):

    if risk_score < 30:
        return "Monitor"

    elif risk_score < 60:
        return "Block 1 min"

    elif risk_score < 80:
        return "Alert + Block 1 min"

    else:
        return "Permanent Block"


def get_risk_level(risk_score):

    if risk_score < 30:
        return "LOW"

    elif risk_score < 60:
        return "MEDIUM"

    elif risk_score < 80:
        return "HIGH"

    else:
        return "CRITICAL"


def get_connection():
    return sqlite3.connect(DATABASE)


def expire_old_rules(cursor):
    """
    Mark expired temporary rules as EXPIRED.
    Permanent blocks do not expire.
    """

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        UPDATE firewall_rules
        SET status = 'EXPIRED'
        WHERE status = 'ACTIVE'
        AND expires_at IS NOT NULL
        AND expires_at <= ?
    """, (now,))


# ================= CHECK BLOCK STATUS =================

def is_ip_blocked(src_ip):
    """
    Return True if the IP has an active temporary
    or permanent HoneyTrack block.
    """

    if not src_ip:
        return False

    conn = get_connection()
    cursor = conn.cursor()

    try:
        expire_old_rules(cursor)

        cursor.execute("""
            SELECT action, expires_at
            FROM firewall_rules
            WHERE src_ip = ?
            AND status = 'ACTIVE'
            ORDER BY id DESC
        """, (src_ip,))

        rules = cursor.fetchall()
        conn.commit()

        if not rules:
            return False

        for action, expires_at in rules:

            if action == "Permanent Block":
                return True

            if expires_at:
                expiry = datetime.strptime(
                    expires_at,
                    "%Y-%m-%d %H:%M:%S"
                )

                if datetime.now() < expiry:
                    return True

        return False

    finally:
        conn.close()


# ================= CREATE FIREWALL RULE =================

def create_firewall_rule(src_ip, risk_score, session_id=None):
    """
    Store a temporary or permanent application-level
    block in the HoneyTrack database.

    This does not modify the Kali operating-system
    firewall. The parser enforces active blocks.
    """

    action = get_firewall_action(risk_score)
    risk_level = get_risk_level(risk_score)

    if action == "Monitor":
        print(f"[FIREWALL] {src_ip} -> Monitor")
        return action

    now = datetime.now()

    expires_at = None

    if action in ("Block 1 min", "Alert + Block 1 min"):

        expires_at = (
            now + timedelta(minutes=BLOCK_DURATION_MINUTES)
        ).strftime("%Y-%m-%d %H:%M:%S")

    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

    reason = (
        f"Risk Level: {risk_level}, "
        f"Risk Score: {risk_score}"
    )

    conn = get_connection()
    cursor = conn.cursor()

    try:
        expire_old_rules(cursor)

        # Check whether this IP already has an active rule.
        cursor.execute("""
            SELECT id, action
            FROM firewall_rules
            WHERE src_ip = ?
            AND status = 'ACTIVE'
            ORDER BY id DESC
            LIMIT 1
        """, (src_ip,))

        existing = cursor.fetchone()

        if existing:

            rule_id, existing_action = existing

            # Never downgrade a permanent block.
            if existing_action == "Permanent Block":
                conn.commit()
                print(
                    f"[FIREWALL] {src_ip} already has "
                    "an active permanent block."
                )
                return existing_action

            # Upgrade an existing temporary rule if
            # the new risk level is higher.
            if risk_score >= 60:

                cursor.execute("""
                    UPDATE firewall_rules
                    SET action = ?,
                        reason = ?,
                        timestamp = ?,
                        expires_at = ?
                    WHERE id = ?
                """, (
                    action,
                    reason,
                    timestamp,
                    expires_at,
                    rule_id
                ))

                conn.commit()

                print(
                    f"[FIREWALL] Rule upgraded for {src_ip}: "
                    f"{action}"
                )

            else:
                conn.commit()

                print(
                    f"[FIREWALL] Existing active rule for "
                    f"{src_ip}: {existing_action}"
                )

                return existing_action

        else:

            cursor.execute("""
                INSERT INTO firewall_rules(
                    timestamp,
                    src_ip,
                    action,
                    reason,
                    status,
                    expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                src_ip,
                action,
                reason,
                "ACTIVE",
                expires_at
            ))

            conn.commit()

        print()
        print("========== HONEYTRACK FIREWALL ==========")
        print(f"Session ID : {session_id}")
        print(f"Source IP  : {src_ip}")
        print(f"Risk Score : {risk_score}")
        print(f"Risk Level : {risk_level}")
        print(f"Action     : {action}")
        print(f"Expires    : {expires_at if expires_at else 'Never'}")
        print("=========================================")
        print()

        return action

    finally:
        conn.close()


# ================= TERMINATE COWRIE SESSION =================

def terminate_session(session_id):
    """
    Terminate an active Cowrie session using
    the HoneyTrack control socket.
    """

    print()
    print("========== SESSION TERMINATION ==========")
    print(f"Session ID: {session_id}")

    try:
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(3)
            sock.connect(COWRIE_SOCKET)
            sock.sendall(session_id.encode("utf-8"))

            response = sock.recv(1024).decode(
                "utf-8"
            ).strip()

        if response == "OK":
            print(
                "Action: Cowrie session terminated successfully."
            )

        elif response == "NOT_FOUND":
            print(
                "Action: Cowrie session was not found."
            )

        else:
            print(f"Action: Cowrie returned: {response}")

    except Exception as e:
        print(f"Action: Failed to terminate session: {e}")

    print("=========================================")
    print()


# ================= MAIN FIREWALL DECISION =================

def process_firewall_decision(
    src_ip,
    risk_score,
    session_id=None
):
    """
    Main firewall function called by parser.py.
    """

    action = create_firewall_rule(
        src_ip,
        risk_score,
        session_id
    )

    if action == "Monitor":
        return action

    elif action == "Block 1 min":

        print(
            f"[FIREWALL ALERT] MEDIUM risk: {src_ip} "
            f"blocked for {BLOCK_DURATION_MINUTES} minute."
        )

        if session_id:
            terminate_session(session_id)

    elif action == "Alert + Block 1 min":

        print()
        print("!!!!!!!! HIGH RISK ALERT !!!!!!!!")
        print(f"Source IP : {src_ip}")
        print(f"Risk Score: {risk_score}")
        print(
            f"Action    : Alert + Block for "
            f"{BLOCK_DURATION_MINUTES} minute"
        )
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print()

        if session_id:
            terminate_session(session_id)

    elif action == "Permanent Block":

        print()
        print("!!!!!!!! CRITICAL THREAT !!!!!!!!")
        print(f"Source IP : {src_ip}")
        print(f"Risk Score: {risk_score}")
        print("Action    : Permanent Block")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print()

        if session_id:
            terminate_session(session_id)

    return action

