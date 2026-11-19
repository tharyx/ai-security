"""Tests for the container SBOM twin."""

from aisec_lab import load_lab_module

c = load_lab_module(__file__, "container_sbom")


def test_os_release_parsed():
    r = c.scan_image(c.IMAGE_FS)
    assert r["os"]["ID"] == "debian" and r["os"]["VERSION_ID"] == "12"


def test_dpkg_only_installed_packages():
    names = {p["name"] for p in c.parse_dpkg(c.DPKG_STATUS)}
    assert names == {"libc6", "openssl"}  # config-files-only package skipped


def test_apk_parsed_with_license():
    pk = {p["name"]: p for p in c.parse_apk(c.APK_INSTALLED)}
    assert pk["musl"]["version"] == "1.2.5-r0" and pk["busybox"]["license"] == "GPL-2.0-only"


def test_purls_carry_distro_context():
    r = c.scan_image(c.IMAGE_FS)
    ssl = next(p for p in r["packages"] if p["name"] == "openssl")
    assert ssl["purl"] == "pkg:deb/debian/openssl@3.0.13-1~deb12u1?arch=amd64&distro=debian-12"


def test_language_packages_found_alongside_os_packages():
    r = c.scan_image(c.IMAGE_FS)
    eco = {p["ecosystem"] for p in r["packages"]}
    assert eco == {"deb", "pypi", "npm"}
    assert any(p["purl"] == "pkg:pypi/flask@3.0.3" for p in r["packages"])


def test_alpine_image():
    r = c.scan_image(c.ALPINE_FS)
    assert {p["ecosystem"] for p in r["packages"]} == {"apk"} and len(r["packages"]) == 2


def test_cyclonedx_for_container():
    doc = c.to_cyclonedx("img", c.scan_image(c.IMAGE_FS))
    assert doc["metadata"]["component"]["type"] == "container"
    assert len(doc["components"]) == 4 and all("purl" in x for x in doc["components"])


def test_empty_image_gives_empty_sbom():
    assert c.scan_image({})["packages"] == []
