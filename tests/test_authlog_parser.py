from app.parsers.authlog_parser import parse_authlog_line


def test_parse_failed_ssh_login():
    line = "Apr 30 10:35:10 jamong sshd[1201]: Failed password for root from 45.12.33.10 port 51120 ssh2"

    event = parse_authlog_line(line, year=2026)

    assert event is not None
    assert event["timestamp"] == "2026-04-30T10:35:10"
    assert event["source"] == "authlog"
    assert event["event_type"] == "ssh_failed_login"
    assert event["src_ip"] == "45.12.33.10"
    assert event["user"] == "root"
    assert event["src_port"] == 51120
    assert event["auth_result"] == "failed"


def test_parse_accepted_ssh_login():
    line = "Apr 30 10:36:52 jamong sshd[1205]: Accepted password for ubuntu from 45.12.33.10 port 51124 ssh2"

    event = parse_authlog_line(line, year=2026)

    assert event is not None
    assert event["timestamp"] == "2026-04-30T10:36:52"
    assert event["source"] == "authlog"
    assert event["event_type"] == "ssh_success_login"
    assert event["src_ip"] == "45.12.33.10"
    assert event["user"] == "ubuntu"
    assert event["src_port"] == 51124
    assert event["auth_result"] == "success"


def test_parse_authlog_line_invalid():
    line = "Apr 30 10:35:10 jamong systemd[1]: Started Session."

    event = parse_authlog_line(line, year=2026)

    assert event is None
