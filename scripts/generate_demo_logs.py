from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote


BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
CONFIG_DIR = BASE_DIR / "config"

NGINX_LOG = SAMPLES_DIR / "nginx_access.log"
AUTH_LOG = SAMPLES_DIR / "auth.log"
ALLOWLIST = CONFIG_DIR / "allowlist.yml"


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
    if user in {"oracle", "test", "guest", "backup", "deploy-old"}:
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


def add_benign_web_traffic(lines: list[str], start: datetime) -> None:
    benign_ips = [
        "198.51.100.10",
        "198.51.100.11",
        "198.51.100.12",
        "203.0.113.20",
        "203.0.113.21",
        "192.0.2.10",
        "192.0.2.11",
    ]
    paths = [
        "/",
        "/index.html",
        "/about",
        "/products",
        "/products?page=2",
        "/contact",
        "/assets/app.js",
        "/assets/style.css",
        "/favicon.ico",
        "/api/status",
    ]

    cursor = start
    count = 0

    for round_index in range(18):
        for ip in benign_ips:
            path = paths[(round_index + count) % len(paths)]
            status = 200 if "favicon" not in path else 404
            lines.append(
                nginx_line(
                    ip=ip,
                    dt=cursor,
                    method="GET",
                    url=path,
                    status=status,
                    size=1024 + (count % 15) * 120,
                    user_agent="Mozilla/5.0",
                )
            )
            cursor += timedelta(seconds=7)
            count += 1


def add_sqli_campaign(lines: list[str], ip: str, start: datetime, rounds: int) -> None:
    payloads = [
        "/product?id=1%27%20OR%20%271%27=%271",
        "/item?id=1%20UNION%20SELECT%201,2,3",
        "/login?id=1%27%20OR%20%271%27=%271",
        "/api/user?id=1%20sleep(5)",
        "/api/user?id=1%20benchmark(1000000,md5(1))",
        "/search?q=1%20UNION%20SELECT%20username,password",
    ]

    for i in range(rounds):
        url = payloads[i % len(payloads)]
        lines.append(
            nginx_line(
                ip=ip,
                dt=start + timedelta(seconds=i * 13),
                method="GET",
                url=url,
                status=403,
                size=300 + i,
                user_agent="sqlmap/1.7",
            )
        )


def add_xss_campaign(lines: list[str], ip: str, start: datetime, rounds: int) -> None:
    payloads = [
        "/search?q=<script>alert(1)</script>",
        "/comment?msg=<script>document.cookie</script>",
        "/profile?name=javascript:alert(1)",
        "/image?src=x%20onerror=alert(1)",
        "/feedback?body=<script>alert(2)</script>",
    ]

    for i in range(rounds):
        lines.append(
            nginx_line(
                ip=ip,
                dt=start + timedelta(seconds=i * 11),
                method="GET",
                url=payloads[i % len(payloads)],
                status=403,
                size=280 + i,
                user_agent="Mozilla/5.0",
            )
        )


def add_path_traversal_campaign(lines: list[str], ip: str, start: datetime, rounds: int) -> None:
    payloads = [
        "/../../etc/passwd",
        "/../../../etc/shadow",
        "/download?file=../../../../etc/passwd",
        "/static/..%2f..%2f..%2fetc%2fpasswd",
        "/../../../../boot.ini",
    ]

    for i in range(rounds):
        lines.append(
            nginx_line(
                ip=ip,
                dt=start + timedelta(seconds=i * 17),
                method="GET",
                url=payloads[i % len(payloads)],
                status=403 if i % 5 != 4 else 404,
                size=210 + i,
                user_agent="curl/8.0",
            )
        )


def add_mixed_web_attack(lines: list[str], ip: str, start: datetime) -> None:
    add_path_traversal_campaign(lines, ip, start, 8)
    add_sqli_campaign(lines, ip, start + timedelta(minutes=2), 12)
    add_xss_campaign(lines, ip, start + timedelta(minutes=5), 6)


def add_auth_bruteforce(
    lines: list[str],
    ip: str,
    start: datetime,
    attempts: int,
    success_after: bool,
    base_pid: int,
    base_port: int,
) -> None:
    users = ["root", "admin", "ubuntu", "oracle", "test", "deploy", "guest", "backup"]

    for i in range(attempts):
        user = users[i % len(users)]
        lines.append(
            auth_failed_line(
                ip=ip,
                dt=start + timedelta(seconds=i * 12),
                pid=base_pid + i,
                user=user,
                port=base_port + i,
            )
        )

    if success_after:
        lines.append(
            auth_success_line(
                ip=ip,
                dt=start + timedelta(seconds=attempts * 12 + 35),
                pid=base_pid + attempts,
                user="ubuntu" if ip != "198.51.100.200" else "root",
                port=base_port + attempts,
            )
        )


def add_allowed_admin_logins(lines: list[str], start: datetime) -> None:
    allowed = [
        ("203.0.113.77", "jamong"),
        ("203.0.113.77", "deploy"),
        ("203.0.113.78", "backup"),
        ("203.0.113.78", "jamong"),
        ("203.0.113.79", "deploy"),
        ("203.0.113.79", "jamong"),
    ]

    for i, (ip, user) in enumerate(allowed):
        lines.append(
            auth_success_line(
                ip=ip,
                dt=start + timedelta(minutes=i * 4),
                pid=3000 + i,
                user=user,
                port=62000 + i,
            )
        )


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
""",
        encoding="utf-8",
    )


def main() -> None:
    SAMPLES_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)

    nginx_lines: list[str] = []
    auth_lines: list[str] = []

    base = datetime(2026, 4, 30, 9, 0, 0)

    add_benign_web_traffic(nginx_lines, base)

    add_mixed_web_attack(nginx_lines, "45.12.33.10", base + timedelta(minutes=45))
    add_sqli_campaign(nginx_lines, "198.51.100.23", base + timedelta(minutes=65), 34)
    add_xss_campaign(nginx_lines, "192.0.2.44", base + timedelta(minutes=82), 28)
    add_path_traversal_campaign(nginx_lines, "203.0.113.88", base + timedelta(minutes=98), 26)
    add_mixed_web_attack(nginx_lines, "91.240.118.22", base + timedelta(minutes=112))
    add_sqli_campaign(nginx_lines, "104.248.90.77", base + timedelta(minutes=128), 22)
    add_xss_campaign(nginx_lines, "45.155.205.111", base + timedelta(minutes=141), 18)
    add_path_traversal_campaign(nginx_lines, "185.220.101.15", base + timedelta(minutes=155), 20)
    add_mixed_web_attack(nginx_lines, "167.99.42.31", base + timedelta(minutes=171))

    add_auth_bruteforce(auth_lines, "45.12.33.10", base + timedelta(minutes=51), 8, True, 1200, 51120)
    add_auth_bruteforce(auth_lines, "185.220.101.15", base + timedelta(minutes=165), 18, False, 1400, 52120)
    add_auth_bruteforce(auth_lines, "198.51.100.200", base + timedelta(minutes=188), 10, True, 1500, 53120)
    add_auth_bruteforce(auth_lines, "91.240.118.22", base + timedelta(minutes=120), 14, False, 1700, 54120)
    add_auth_bruteforce(auth_lines, "104.248.90.77", base + timedelta(minutes=135), 9, False, 1800, 55120)
    add_auth_bruteforce(auth_lines, "167.99.42.31", base + timedelta(minutes=180), 12, True, 1900, 56120)
    add_auth_bruteforce(auth_lines, "203.0.113.90", base + timedelta(minutes=200), 6, False, 2000, 57120)
    add_auth_bruteforce(auth_lines, "203.0.113.91", base + timedelta(minutes=207), 5, False, 2100, 58120)

    add_allowed_admin_logins(auth_lines, base + timedelta(minutes=230))

    nginx_lines.sort()
    auth_lines.sort()

    NGINX_LOG.write_text("\n".join(nginx_lines) + "\n", encoding="utf-8")
    AUTH_LOG.write_text("\n".join(auth_lines) + "\n", encoding="utf-8")
    write_allowlist()

    print(f"[+] Wrote {len(nginx_lines)} nginx log lines to {NGINX_LOG}")
    print(f"[+] Wrote {len(auth_lines)} auth log lines to {AUTH_LOG}")
    print(f"[+] Total demo events: {len(nginx_lines) + len(auth_lines)}")
    print(f"[+] Wrote allowlist to {ALLOWLIST}")


if __name__ == "__main__":
    main()
