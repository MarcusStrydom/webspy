import json
from pathlib import Path

import webspy


def test_version():
    assert webspy.__version__


def test_packaged_config_loads():
    spy = webspy.Passive()
    assert spy.list_probes()
    assert set(webspy.AUDIT_PROFILES) >= {"quick", "standard", "full"}


def test_all_config_sections_present():
    cfg_dir = Path(webspy.__file__).parent / "config"
    for section in webspy.SECTIONS:
        json.loads((cfg_dir / f"{section}.json").read_text(encoding="utf-8"))


def test_cli_list_probes(capsys):
    assert webspy.main(["--list-probes"]) == 0
    assert "get_tls_info" in capsys.readouterr().out


def test_cli_requires_authorisation_for_active_probe():
    import pytest
    with pytest.raises(SystemExit):
        webspy.main(["example.com", "--probe", "get_port_scan"])
