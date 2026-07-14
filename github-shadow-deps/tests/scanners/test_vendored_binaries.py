"""Tests for vendored binary file detection."""
from __future__ import annotations

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.vendored_binaries import VendoredBinaryScanner


def scan(path, rel_path: str | None = None):
    scanner = VendoredBinaryScanner(Config())
    target = FileTarget(path=path, rel_path=rel_path or path.name, file_type="binary")
    return scanner.scan_file(target)


def test_reports_checked_in_executable_by_extension(tmp_path):
    binary = tmp_path / "helper.exe"
    binary.write_bytes(b"MZ\x00\x00")

    findings = scan(binary, "scripts/helper.exe")

    assert any(
        f.pattern_id == "vendored-executable"
        and f.extracted_dep == "scripts/helper.exe"
        for f in findings
    )


def test_ignores_executable_in_test_fixture_path(tmp_path):
    binary = tmp_path / "test.exe"
    binary.write_bytes(b"MZ\x00\x00")

    findings = scan(binary, "test/tools/llvm-symbolizer/pdb/Inputs/test.exe")

    assert findings == []


def test_ignores_static_library_in_test_input_path(tmp_path):
    binary = tmp_path / "libsimple_archive.a"
    binary.write_bytes(b"!<arch>\x00")

    findings = scan(binary, "test/Object/Inputs/libsimple_archive.a")

    assert findings == []


def test_ignores_java_artifact_in_test_tree(tmp_path):
    binary = tmp_path / "test.jar"
    binary.write_bytes(b"PK\x03\x04\x00")

    findings = scan(binary, "test/jdk/java/util/jar/JarFile/test.jar")

    assert findings == []


def test_ignores_legacy_tests_data_binary(tmp_path):
    binary = tmp_path / "testAssembly1.dll"
    binary.write_bytes(b"MZ\x00\x00")

    findings = scan(binary, "Tests-Legacy/L0/VsTestV1/data/testDlls/testAssembly1.dll")

    assert findings == []


def test_ignores_large_binary_blob_in_test_data(tmp_path):
    binary = tmp_path / "truth.bin"
    binary.write_bytes(b"\x00" + (b"x" * (101 * 1024)))

    findings = scan(binary, "test_data/disk_index_search/truth.bin")

    assert findings == []


def test_ignores_binary_in_e2e_ports_fixture_path(tmp_path):
    binary = tmp_path / "test_dll.dll"
    binary.write_bytes(b"MZ\x00\x00")

    findings = scan(binary, "azure-pipelines/e2e-ports/vcpkg-msvc-2013/debug/test_dll.dll")

    assert findings == []


def test_ignores_binary_in_e2etest_sample_adapter_path(tmp_path):
    binary = tmp_path / "Microsoft.VisualStudio.TestPlatform.MSTest.TestAdapter.dll"
    binary.write_bytes(b"MZ\x00\x00")

    findings = scan(
        binary,
        "samples/Microsoft.TestPlatform.E2ETest/Adapter/"
        "Microsoft.VisualStudio.TestPlatform.MSTest.TestAdapter.dll",
    )

    assert findings == []


def test_keeps_sample_executable_reported(tmp_path):
    binary = tmp_path / "DataCollectorSGM.exe"
    binary.write_bytes(b"MZ\x00\x00")

    findings = scan(binary, "Examples/DataCollection/exe/DataCollectorSGM.exe")

    assert any(
        f.pattern_id == "vendored-executable"
        and f.extracted_dep == "Examples/DataCollection/exe/DataCollectorSGM.exe"
        for f in findings
    )


def test_keeps_non_test_java_artifact_reported(tmp_path):
    binary = tmp_path / "tool.jar"
    binary.write_bytes(b"PK\x03\x04\x00")

    findings = scan(binary, "tools/lib/tool.jar")

    assert any(
        f.pattern_id == "vendored-java-artifact"
        and f.extracted_dep == "tools/lib/tool.jar"
        for f in findings
    )


def test_ignores_small_generic_bin_sample_data(tmp_path):
    binary = tmp_path / "Avocado.bin"
    binary.write_bytes(b"\x00sample model payload")

    findings = scan(binary, "Samples/BulkLoadDemo/BulkLoadDemo/SampleModel/Avocado.bin")

    assert findings == []


def test_reports_large_generic_bin_blob(tmp_path):
    binary = tmp_path / "weights.bin"
    binary.write_bytes(b"\x00" + (b"x" * (101 * 1024)))

    findings = scan(binary, "models/weights.bin")

    assert any(
        f.pattern_id == "large-binary-blob"
        and f.extracted_dep == "models/weights.bin"
        for f in findings
    )


def test_ignores_large_font_file(tmp_path):
    font = tmp_path / "Roboto-Regular.ttf"
    font.write_bytes(b"\x00" + (b"x" * (101 * 1024)))

    findings = scan(font, "Resources/Fonts/Roboto-Regular.ttf")

    assert findings == []
