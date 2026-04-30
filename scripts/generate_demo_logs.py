from __future__ import annotations

import argparse
from datetime import datetime, timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
CONFIG_DIR = BASE_DIR / "config"

NGINX_LOG = SAMPLES_DIR / "nginx_access.log"
AUTH_LOG = SAMPLES_DIR / "auth.log"
ALLOWLIST = CONFIG_DIR / "allowlist.yml"


BENIGN_IPS = [
    "198.51.100.10",
    "198.51.100.11",
    "198.51.100.12",
    "203.0.113.20",
    "203.0.113.21",
    "192.0.2.10",
    "192.0.2.11",
    "198.51.100.30",
    "198.51.100.31",
    "192.0.2.30",
]

ATTACK_IPS = [
    "45.12.33.10",
    "198.51.100.23",
    "192.0.2.44",
    "203.0.113.88",
    "91.240.118.22",
    "104.248.90.77",
    "45.155.205.111",
    "185.220.101.15",
    "167.99.42.31",
    "198.51.100.200",
    "203.0.113.90",
    "203.0.113.91",
    "64.227.18.90",
    "143.198.77.21",
    "178.128.94.18",
    "159.65.203.44",
    "139.59.12.88",
    "206.189.45.19",
    "188.166.21.70",
    "157.245.33.10",
]

ADMIN_USERS_BY_IP = {
    "203.0.113.77": ["jamong", "deploy"],
    "203.0.113.78": ["backup", "jamong"],
    "203.0.113.79": ["deploy", "jamong"],
}


def nginx_line(
    ip: str,
    dt: datetime,
    method: str,
    url: str,
    status: int,
    size: int,
    user_agent: str,
) -> str:
    timestamp = dt.strftime("%d/%b/%Y:%H:%M:%S +0900")
    return (
        f'{ip} - - [{timestamp}] '
        f'"{method} {url} HTTP/1.1" {status} {size} "-" "{user_agent}"'
    )


def auth_failed_line(ip: str, dt: datetime, pid: int, user: str, port: int) -> str:
    timestamp = dt.strftime("%b %d %H:%M:%S")
    invalid_users = {"oracle", "test", "guest", "backup", "deploy-old", "mysql", "postgres"}

    if user in invalid_users:
        return (
            f"{timestamp} jamong sshd[{pid}]: "
            f"Failed password for invalid user {user} from {ip} port {port} ssh2"
        )

    return (
        f"{timestamp} jamong sshd[{pid}]: "
        f"Failed password for {user} from {ip} port {port} ssh2"
    )


def auth_success_line(ip: str, dt: datetime, pid: int, user: str, port: int) -> str:
    timestamp = dt.strftime("%b %d %H:%M:%S")
    return (
        f"{timestamp} jamong sshd[{pid}]: "
        f"Accepted password for {user} from {ip} port {port} ssh2"
    )


def add_benign_web_traffic(lines: list[str], start: datetime, count: int) -> None:
    paths = [
        "/",
        "/index.html",
        "/about",
        "/products",
        "/products?page=2",
        "/products?page=3",
        "/contact",
        "/assets/app.js",
        "/assets/style.css",
        "/assets/logo.png",
        "/favicon.ico",
        "/api/status",
        "/api/products",
        "/health",
    ]

    cursor = start

    for i in range(count):
        ip = BENIGN_IPS[i % len(BENIGN_IPS)]
        path = paths[i % len(paths)]
        status = 200 if path != "/favicon.ico" else 404

        lines.append(
            nginx_line(
                ip=ip,
                dt=cursor,
                method="GET",
                url=path,
                status=status,
                size=900 + (i % 30) * 73,
                user_agent="Mozilla/5.0",
            )
        )

        cursor += timedelta(seconds=3)


def add_policy_suppression_web_traffic(lines: list[str], start: datetime, count: int) -> None:
    """
    Generate web requests that intentionally trigger WEB-SCAN-001 first,
    then get suppressed by different suppression policy types.

    Policy types covered:
    - suppressed_rules
    - suppressed_user_agents
    - suppressed_paths
    - trusted_services
    - trusted_networks
    - maintenance_windows
    """
    cases = [
        # suppressed_rules: specific rule_id + src_ip
        {
            "ip": "198.51.100.10",
            "path": "/admin",
            "ua": "python-requests/2.31",
            "time_base": start,
        },
        {
            "ip": "198.51.100.11",
            "path": "/phpmyadmin",
            "ua": "nikto/2.5.0",
            "time_base": start,
        },
        {
            "ip": "198.51.100.12",
            "path": "/.env",
            "ua": "curl/8.0",
            "time_base": start,
        },
        {
            "ip": "198.51.100.30",
            "path": "/wp-admin",
            "ua": "python-requests/2.31",
            "time_base": start,
        },
        {
            "ip": "198.51.100.31",
            "path": "/server-status",
            "ua": "curl/8.0",
            "time_base": start,
        },

        # suppressed_user_agents: user-agent based policy
        {
            "ip": "192.0.2.60",
            "path": "/server-status",
            "ua": "Uptime-Kuma/1.23",
            "time_base": start + timedelta(minutes=40),
        },
        {
            "ip": "192.0.2.61",
            "path": "/server-status",
            "ua": "Prometheus/2.0",
            "time_base": start + timedelta(minutes=40),
        },
        {
            "ip": "192.0.2.62",
            "path": "/server-status",
            "ua": "ELB-HealthChecker/2.0",
            "time_base": start + timedelta(minutes=40),
        },
        {
            "ip": "192.0.2.63",
            "path": "/server-status",
            "ua": "GoogleHC/1.0",
            "time_base": start + timedelta(minutes=40),
        },

        # suppressed_paths: path-based policy. curl triggers WEB-SCAN-001.
        {
            "ip": "192.0.2.70",
            "path": "/server-status",
            "ua": "curl/8.0",
            "time_base": start + timedelta(minutes=80),
        },
        {
            "ip": "192.0.2.71",
            "path": "/.well-known/security.txt",
            "ua": "curl/8.0",
            "time_base": start + timedelta(minutes=80),
        },
        {
            "ip": "192.0.2.72",
            "path": "/health",
            "ua": "curl/8.0",
            "time_base": start + timedelta(minutes=80),
        },
        {
            "ip": "192.0.2.73",
            "path": "/api/status",
            "ua": "curl/8.0",
            "time_base": start + timedelta(minutes=80),
        },

        # trusted_services
        {
            "ip": "198.51.100.50",
            "path": "/admin",
            "ua": "GitHub-Hookshot/abc123",
            "time_base": start + timedelta(minutes=120),
        },
        {
            "ip": "198.51.100.51",
            "path": "/admin",
            "ua": "Slackbot-LinkExpanding 1.0",
            "time_base": start + timedelta(minutes=120),
        },
        {
            "ip": "198.51.100.52",
            "path": "/server-status",
            "ua": "Pingdom.com_bot_version_1.4",
            "time_base": start + timedelta(minutes=120),
        },
        {
            "ip": "198.51.100.53",
            "path": "/server-status",
            "ua": "StatusCake",
            "time_base": start + timedelta(minutes=120),
        },

        # maintenance_windows: must fall into 04:00~04:30.
        {
            "ip": "45.12.33.200",
            "path": "/admin",
            "ua": "curl/8.0",
            "time_base": datetime(2026, 4, 30, 4, 5, 0),
        },
        {
            "ip": "45.12.33.201",
            "path": "/phpmyadmin",
            "ua": "nikto/2.5.0",
            "time_base": datetime(2026, 4, 30, 4, 10, 0),
        },
    ]

    for i in range(count):
        case = cases[i % len(cases)]
        dt = case["time_base"] + timedelta(seconds=(i // len(cases)) * 9)

        lines.append(
            nginx_line(
                ip=case["ip"],
                dt=dt,
                method="GET",
                url=case["path"],
                status=403 if i % 3 == 0 else 404,
                size=160 + (i % 80),
                user_agent=case["ua"],
            )
        )


def add_external_attack_web_traffic(lines: list[str], start: datetime, count: int) -> None:
    """
    Generate unsuppressed external web attacks with varied attack types.

    These should remain visible in alerts/incidents.
    """
    attack_cases = [
        {
            "path": "/../../etc/passwd",
            "ua": "curl/8.0",
            "status": 403,
        },
        {
            "path": "/../../../etc/shadow",
            "ua": "curl/8.0",
            "status": 403,
        },
        {
            "path": "/download?file=../../../../etc/passwd",
            "ua": "curl/8.0",
            "status": 403,
        },
        {
            "path": "/product?id=1%27%20OR%20%271%27=%271",
            "ua": "sqlmap/1.7",
            "status": 403,
        },
        {
            "path": "/item?id=1%20UNION%20SELECT%201,2,3",
            "ua": "sqlmap/1.7",
            "status": 403,
        },
        {
            "path": "/api/user?id=1%20sleep(5)",
            "ua": "sqlmap/1.7",
            "status": 403,
        },
        {
            "path": "/search?q=<script>alert(1)</script>",
            "ua": "Mozilla/5.0",
            "status": 403,
        },
        {
            "path": "/comment?msg=<script>document.cookie</script>",
            "ua": "Mozilla/5.0",
            "status": 403,
        },
        {
            "path": "/profile?name=javascript:alert(1)",
            "ua": "Mozilla/5.0",
            "status": 403,
        },
        {
            "path": "/admin",
            "ua": "python-requests/2.31",
            "status": 404,
        },
        {
            "path": "/.env",
            "ua": "python-requests/2.31",
            "status": 404,
        },
        {
            "path": "/wp-admin",
            "ua": "nikto/2.5.0",
            "status": 404,
        },
    ]

    cursor = start

    for i in range(count):
        # Change source IP every 70 events to create realistic repeated campaigns,
        # but not so aggressively that every event becomes a separate incident.
        ip = ATTACK_IPS[(i // 70) % len(ATTACK_IPS)]
        case = attack_cases[i % len(attack_cases)]

        lines.append(
            nginx_line(
                ip=ip,
                dt=cursor,
                method="GET",
                url=case["path"],
                status=case["status"],
                size=220 + (i % 200),
                user_agent=case["ua"],
            )
        )

        # Some slow-ish spacing so dedup does not collapse everything into one alert.
        cursor += timedelta(seconds=11 + (i % 5))


def add_auth_attack_traffic(lines: list[str], start: datetime, count: int) -> None:
    users = [
        "root",
        "admin",
        "ubuntu",
        "oracle",
        "test",
        "deploy",
        "guest",
        "backup",
        "mysql",
        "postgres",
    ]

    cursor = start

    for i in range(count):
        block_index = i // 25
        position = i % 25
        ip = ATTACK_IPS[block_index % len(ATTACK_IPS)]

        # Every 25-event block has repeated failures and occasionally one success.
        if position == 24 and block_index % 3 == 0:
            user = "root" if ip == "198.51.100.200" else "ubuntu"
            lines.append(
                auth_success_line(
                    ip=ip,
                    dt=cursor,
                    pid=5000 + i,
                    user=user,
                    port=55000 + i,
                )
            )
        else:
            user = users[i % len(users)]
            lines.append(
                auth_failed_line(
                    ip=ip,
                    dt=cursor,
                    pid=5000 + i,
                    user=user,
                    port=55000 + i,
                )
            )

        cursor += timedelta(seconds=12)


def add_allowed_admin_logins(lines: list[str], start: datetime, count: int) -> None:
    admin_ips = list(ADMIN_USERS_BY_IP.keys())
    cursor = start

    for i in range(count):
        ip = admin_ips[i % len(admin_ips)]
        users = ADMIN_USERS_BY_IP[ip]
        user = users[i % len(users)]

        lines.append(
            auth_success_line(
                ip=ip,
                dt=cursor,
                pid=8000 + i,
                user=user,
                port=62000 + i,
            )
        )

        cursor += timedelta(minutes=2)


def write_allowlist() -> None:
    ALLOWLIST.write_text(
        """allowed_ssh_logins:
  - src_ip: 203.0.113.77
    user: jamong
    reason: Known administrator login from trusted IP
  - src_ip: 203.0.113.77
    user: deploy
    reason: Known deploy account from trusted IP
  - src_ip: 203.0.113.78
    user: backup
    reason: Known backup automation from trusted IP
  - src_ip: 203.0.113.78
    user: jamong
    reason: Known administrator login from trusted IP
  - src_ip: 203.0.113.79
    user: deploy
    reason: Known deployment host from trusted IP
  - src_ip: 203.0.113.79
    user: jamong
    reason: Known administrator login from trusted IP

suppressed_rules:
  - rule_id: WEB-SCAN-001
    src_ip: 198.51.100.10
    reason: Internal vulnerability scanner
  - rule_id: WEB-SCAN-001
    src_ip: 198.51.100.11
    reason: Internal vulnerability scanner
  - rule_id: WEB-SCAN-001
    src_ip: 198.51.100.12
    reason: Internal vulnerability scanner
  - rule_id: WEB-SCAN-001
    src_ip: 198.51.100.30
    reason: Scheduled internal web exposure scan
  - rule_id: WEB-SCAN-001
    src_ip: 198.51.100.31
    reason: Scheduled internal web exposure scan

suppressed_user_agents:
  - user_agent_contains: Uptime-Kuma
    rule_id: WEB-SCAN-001
    reason: Internal uptime monitoring probe
  - user_agent_contains: Prometheus
    rule_id: WEB-SCAN-001
    reason: Internal metrics scraper
  - user_agent_contains: ELB-HealthChecker
    rule_id: WEB-SCAN-001
    reason: Load balancer health check
  - user_agent_contains: GoogleHC
    rule_id: WEB-SCAN-001
    reason: Cloud health check probe

suppressed_paths:
  - path_contains: /server-status
    src_ip: 192.0.2.70
    reason: Approved Apache status endpoint check
  - path_contains: /.well-known/security.txt
    reason: Security contact discovery request
  - path_contains: /health
    reason: Application health check endpoint
  - path_contains: /api/status
    reason: Application status check endpoint

trusted_services:
  - src_ip: 198.51.100.50
    user_agent_contains: GitHub-Hookshot
    reason: Known CI/CD webhook source
  - src_ip: 198.51.100.51
    user_agent_contains: Slackbot
    reason: Known Slack link unfurl bot
  - src_ip: 198.51.100.52
    user_agent_contains: Pingdom
    reason: Approved external monitoring service
  - src_ip: 198.51.100.53
    user_agent_contains: StatusCake
    reason: Approved uptime monitoring service

trusted_networks:
  - cidr: 203.0.113.0/24
    suppress_event_types:
      - ssh_success_login
    reason: Trusted administration network
  - cidr: 198.51.100.0/24
    suppress_rule_ids:
      - WEB-SCAN-001
    reason: Trusted internal scanning network

maintenance_windows:
  - start: "2026-04-30T02:00:00"
    end: "2026-04-30T03:00:00"
    suppress_rule_ids:
      - SSH-SUCCESS-001
    reason: Scheduled maintenance SSH access
  - start: "2026-04-30T04:00:00"
    end: "2026-04-30T04:30:00"
    suppress_rule_ids:
      - WEB-SCAN-001
    reason: Scheduled web assessment window
""",
        encoding="utf-8",
    )


def build_dataset(target_events: int) -> tuple[list[str], list[str]]:
    if target_events < 500:
        target_events = 500

    nginx_lines: list[str] = []
    auth_lines: list[str] = []

    base = datetime(2026, 4, 30, 9, 0, 0)

    nginx_target = int(target_events * 0.82)
    auth_target = target_events - nginx_target

    benign_count = int(target_events * 0.38)
    policy_suppression_web_count = int(target_events * 0.12)
    attack_web_count = nginx_target - benign_count - policy_suppression_web_count

    admin_login_count = int(target_events * 0.03)
    auth_attack_count = auth_target - admin_login_count

    add_benign_web_traffic(
        nginx_lines,
        base,
        benign_count,
    )

    add_policy_suppression_web_traffic(
        nginx_lines,
        base + timedelta(hours=1),
        policy_suppression_web_count,
    )

    add_external_attack_web_traffic(
        nginx_lines,
        base + timedelta(hours=2),
        attack_web_count,
    )

    add_auth_attack_traffic(
        auth_lines,
        base + timedelta(hours=4),
        auth_attack_count,
    )

    add_allowed_admin_logins(
        auth_lines,
        base + timedelta(hours=8),
        admin_login_count,
    )

    nginx_lines.sort()
    auth_lines.sort()

    return nginx_lines, auth_lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate synthetic SOC demo logs for dashboard testing."
    )

    parser.add_argument(
        "--events",
        type=int,
        default=1000,
        help="Exact total number of demo events to generate. Example: 10000",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    SAMPLES_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)

    nginx_lines, auth_lines = build_dataset(args.events)

    NGINX_LOG.write_text("\n".join(nginx_lines) + "\n", encoding="utf-8")
    AUTH_LOG.write_text("\n".join(auth_lines) + "\n", encoding="utf-8")
    write_allowlist()

    print(f"[+] Target demo events: {args.events}")
    print(f"[+] Wrote {len(nginx_lines)} nginx log lines to {NGINX_LOG}")
    print(f"[+] Wrote {len(auth_lines)} auth log lines to {AUTH_LOG}")
    print(f"[+] Total demo events: {len(nginx_lines) + len(auth_lines)}")
    print(f"[+] Wrote suppression policy to {ALLOWLIST}")


if __name__ == "__main__":
    main()
