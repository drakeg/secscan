from __future__ import annotations

import pytest

from secscan.scanners.linux_host import _build_trivy_sbom, _parse_output


BASE = """os_kernel\tLinux
kernel_release\t6.8.0
os_id\tdebian
os_version\t12
uid0_accounts\troot
ssh_password_auth\tno
ssh_root_login\tprohibit-password
pending_updates\t0
firewall_state\tactive
world_writable_etc\t
package_manager\tdpkg
"""


def test_dpkg_source_metadata_is_preserved_and_added_to_trivy_properties() -> None:
    output = BASE + "package\tlibssl3\t3.0.17-1~deb12u2\tamd64\topenssl\t3.0.17-1~deb12u2\n"
    values, packages = _parse_output(output)

    assert packages == [
        {
            "name": "libssl3",
            "version": "3.0.17-1~deb12u2",
            "architecture": "amd64",
            "source_name": "openssl",
            "source_version": "3.0.17-1~deb12u2",
            "source": "dpkg",
        }
    ]

    sbom = _build_trivy_sbom(values, packages, "debian.example")
    assert sbom is not None
    component = sbom["components"][0]  # type: ignore[index]
    properties = {
        item["name"]: item["value"]  # type: ignore[index]
        for item in component["properties"]  # type: ignore[index,union-attr]
    }
    assert properties["aquasecurity:trivy:SrcName"] == "openssl"
    assert properties["aquasecurity:trivy:SrcVersion"] == "3.0.17-1~deb12u2"


def test_dpkg_missing_source_field_uses_policy_defined_binary_identity() -> None:
    output = BASE + "package\tzlib1g\t1:1.2.13.dfsg-1\tamd64\t\t\n"
    _values, packages = _parse_output(output)

    assert packages[0]["source_name"] == "zlib1g"
    assert packages[0]["source_version"] == "1:1.2.13.dfsg-1"


def test_source_metadata_must_be_complete() -> None:
    output = BASE + "package\tlibssl3\t3.0.17\tamd64\topenssl\t\n"
    with pytest.raises(ValueError, match="incomplete source package metadata"):
        _parse_output(output)


def test_legacy_rpm_rows_do_not_gain_guessed_source_metadata() -> None:
    output = BASE.replace("package_manager\tdpkg", "package_manager\trpm")
    output += "package\tzlib\t1:1.3.1-2\tx86_64\n"
    _values, packages = _parse_output(output)

    assert packages == [
        {
            "name": "zlib",
            "version": "1:1.3.1-2",
            "architecture": "x86_64",
            "source": "rpm",
        }
    ]
