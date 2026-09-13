from pathlib import Path
import tomllib
import xml.etree.ElementTree as ET


ROOT = Path(__file__).parents[1]


def test_manifest_exposes_only_health_check():
    manifest = tomllib.loads((ROOT / "cloudinabottle.toml").read_text())

    assert manifest["app"]["name"] == "freshrss"
    assert manifest["runtime"]["container"]["port"] == 8080
    assert manifest["routing"]["health_check"] == "/healthz"
    assert manifest["routing"]["public_paths"] == ["/healthz"]
    assert manifest["data"] == {"app_data": True}


def test_default_opml_contains_no_feeds():
    root = ET.parse(ROOT / "opml.default.xml").getroot()

    assert root.tag == "opml"
    assert root.findall(".//outline") == []


def test_image_is_pinned_to_a_release():
    dockerfile = (ROOT / "Dockerfile").read_text()

    assert "FROM freshrss/freshrss:1.30.0-alpine" in dockerfile
    assert ":latest" not in dockerfile
    assert ":edge" not in dockerfile


def test_owner_creation_explicitly_disables_default_feeds():
    entrypoint = (ROOT / "start.sh").read_text()

    assert "--no-default-feeds" in entrypoint
