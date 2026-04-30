from app.parsers.suricata_parser import parse_suricata_eve_line


def test_parse_suricata_eve_alert_line():
    line = (
        '{"timestamp":"2026-04-30T11:02:00+09:00",'
        '"event_type":"alert",'
        '"src_ip":"45.12.33.10",'
        '"dest_ip":"10.0.0.5",'
        '"proto":"TCP",'
        '"src_port":40000,'
        '"dest_port":80,'
        '"alert":{"signature":"ET WEB_SERVER SQL Injection Attempt",'
        '"category":"Web Application Attack",'
        '"severity":1}}'
    )

    event = parse_suricata_eve_line(line)

    assert event is not None
    assert event["source"] == "suricata"
    assert event["event_type"] == "ids_alert"
    assert event["src_ip"] == "45.12.33.10"
    assert event["dest_ip"] == "10.0.0.5"
    assert event["signature"] == "ET WEB_SERVER SQL Injection Attempt"
    assert event["category"] == "Web Application Attack"
    assert event["suricata_severity"] == 1
    assert event["dest_port"] == 80


def test_ignore_non_alert_suricata_event():
    line = '{"timestamp":"2026-04-30T11:02:00+09:00","event_type":"flow","src_ip":"1.1.1.1"}'

    event = parse_suricata_eve_line(line)

    assert event is None


def test_ignore_invalid_json_line():
    event = parse_suricata_eve_line("not-json")

    assert event is None
