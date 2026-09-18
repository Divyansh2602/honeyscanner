import json
from pathlib import Path
from typing import Any

from honeyscanner.report_generator import ReportGenerator


class MockHoneypot:
    def __init__(self) -> None:
        self.name = "cowrie"
        self.version = "2.5.0"
        self.ip = "127.0.0.1"
        self.ports = [22, 2222]


def test_generate_report_dict() -> None:
    honeypot: Any = MockHoneypot()
    generator = ReportGenerator(honeypot)
    recommendations = ["Update SSH credentials", "Disable root login"]
    passive_results = "Cowrie honeypot detected on port 22."
    active_results = ("DoS attack completed.", 0, 0)

    report = generator.generate(recommendations, passive_results, active_results)

    assert "metadata" in report
    assert "results" in report
    assert "recommendations" in report
    assert report["metadata"]["honeypot"]["name"] == "cowrie"
    assert report["metadata"]["honeypot"]["ip"] == "127.0.0.1"
    assert report["recommendations"] == recommendations


def test_save_json_report(tmp_path: Path) -> None:
    honeypot: Any = MockHoneypot()
    generator = ReportGenerator(honeypot)
    recommendations = ["Recommendation 1"]
    passive_results = "Passive scan ok"
    active_results = ("Active scan ok", 0, 0)

    report = generator.generate(recommendations, passive_results, active_results)
    json_path = generator.save_json(report, output_dir=tmp_path)

    assert json_path.exists()
    assert json_path.suffix == ".json"

    with open(json_path, "r", encoding="utf-8") as f:
        loaded_report = json.load(f)

    assert loaded_report["metadata"]["honeypot"]["name"] == "cowrie"
    assert loaded_report["results"]["passive"] == "Passive scan ok"
    assert loaded_report["recommendations"] == ["Recommendation 1"]
