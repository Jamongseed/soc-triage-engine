from app.parsers.nginx_parser import parse_nginx_line


def test_parse_nginx_line_success():
    line = '45.12.33.10 - - [30/Apr/2026:10:31:02 +0900] "GET /product?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 403 312 "-" "sqlmap/1.7"'

    event = parse_nginx_line(line)

    assert event is not None
    assert event["timestamp"] == "2026-04-30T10:31:02+09:00"
    assert event["source"] == "nginx"
    assert event["event_type"] == "web_request"
    assert event["src_ip"] == "45.12.33.10"
    assert event["method"] == "GET"
    assert event["url"] == "/product?id=1' OR '1'='1"
    assert event["status"] == 403
    assert event["user_agent"] == "sqlmap/1.7"


def test_parse_nginx_line_invalid():
    line = "this is not a valid nginx log"

    event = parse_nginx_line(line)

    assert event is None
