from secscan.report import build_report


def test_image_report_target_type_remains_backward_compatible() -> None:
    report = build_report("alpine:3.20", [], {"name": "trivy"})

    assert report["target"]["type"] == "container_image"


def test_filesystem_report_target_type_is_recorded() -> None:
    report = build_report("/scan", [], {"name": "trivy"}, target_type="filesystem")

    assert report["target"]["type"] == "filesystem"
