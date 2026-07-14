"""Tests for CDNReferenceScanner."""
from __future__ import annotations

from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.cdn_references import CDNReferenceScanner


def scan(content: str, rel_path: str = "index.html", file_type: str = "web_asset"):
    scanner = CDNReferenceScanner(Config())
    target = FileTarget(path=Path(rel_path), rel_path=rel_path, file_type=file_type)
    return scanner.scan_file_content(target, content, content.splitlines())


def test_ignores_local_development_script_origin():
    findings = scan('<script src="https://monaco.local/Assets/vs/loader.js"></script>\n')

    assert not any(f.pattern_id == "script-tag-external" for f in findings)


def test_ignores_templated_local_webview_origin():
    findings = scan(
        '<script src="http://[[PT_URL]]/monacoSRC/min/vs/loader.js"></script>\n'
        'import { x } from "http://[[PT_URL]]/monacoSpecialLanguages.js";\n'
    )

    assert not any(f.category.value == "cdn-reference" for f in findings)


def test_ignores_single_label_local_webview_origin():
    findings = scan(
        '<script src="http://PowerToysLocalMonaco/monacoSRC/min/vs/loader.js"></script>\n'
        'import { x } from "http://PowerToysLocalMonaco/customTokenThemeRules.js";\n'
    )

    assert not any(f.category.value == "cdn-reference" for f in findings)


def test_detects_public_external_script_origin():
    findings = scan('<script src="https://cdn.example.com/lib.js"></script>\n')

    assert any(
        f.pattern_id == "script-tag-external"
        and f.extracted_dep == "https://cdn.example.com/lib.js"
        for f in findings
    )


def test_ignores_cdn_reference_in_test_web_asset_path():
    findings = scan(
        '<script src="https://unpkg.com/react@17/umd/react.development.js"></script>\n',
        rel_path="test/sanddance-app.html",
    )

    assert findings == []


def test_ignores_cdn_reference_in_docs_tests_path():
    findings = scan(
        '<script src="https://unpkg.com/vega@^6.2/build/vega.js"></script>\n',
        rel_path="docs/tests/v4/umd/test.html",
    )

    assert findings == []


def test_ignores_cdn_reference_in_functional_tests_path():
    findings = scan(
        '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">\n',
        rel_path="functional_tests/table_validation_final.html",
    )

    assert findings == []


def test_keeps_cdn_reference_in_docs_embed_page():
    findings = scan(
        '<script src="https://unpkg.com/@msrvida/sanddance-embed@4.4/dist/umd/sanddance-embed.js"></script>\n',
        rel_path="docs/embed/v4/sanddance-embed.html",
    )

    assert any(
        f.pattern_id == "script-tag-external"
        and f.extracted_dep == "https://unpkg.com/@msrvida/sanddance-embed@4.4/dist/umd/sanddance-embed.js"
        for f in findings
    )


def test_keeps_cdn_reference_in_sample_page():
    findings = scan(
        '<script src="https://unpkg.com/@fluentui/web-components@beta/dist/web-components.min.js"></script>\n',
        rel_path="plugins/mcp-apps/samples/flight-status-widget.html",
    )

    assert any(
        f.pattern_id == "script-tag-external"
        and f.extracted_dep == "https://unpkg.com/@fluentui/web-components@beta/dist/web-components.min.js"
        for f in findings
    )


def test_ignores_cdn_reference_in_mkdocs_generated_html():
    findings = scan(
        '<!doctype html>\n'
        '<html><head>\n'
        '<meta name="generator" content="mkdocs-1.6.1, mkdocs-material-9.1.15">\n'
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto&display=fallback">\n'
        '</head><body></body></html>\n',
        rel_path="docs/support/site/HOBL_Parameters.html",
    )

    assert findings == []


def test_ignores_script_tag_inside_html_comment():
    findings = scan('<!--<script src="http://cdnjs.cloudflare.com/ajax/libs/vue/1.0.16/vue.min.js"></script>-->\n')

    assert not any(f.pattern_id == "script-tag-external" for f in findings)


def test_ignores_json_schema_metadata_in_package_config():
    findings = scan(
        '{\n  "$schema": "https://json.schemastore.org/package.json",\n  "name": "demo"\n}\n',
        rel_path="package.json",
        file_type="package_config",
    )

    assert not any(f.pattern_id == "json-schema-url" for f in findings)
    assert not any(f.category.value == "cdn-reference" for f in findings)


def test_ignores_json_schema_metadata_in_vcpkg_config():
    findings = scan(
        '{\n'
        '  "$schema": "https://raw.githubusercontent.com/microsoft/vcpkg-tool/main/docs/vcpkg.schema.json",\n'
        '  "name": "demo"\n'
        '}\n',
        rel_path="vcpkg.json",
        file_type="vcpkg_config",
    )

    assert not any(f.pattern_id == "json-schema-url" for f in findings)
    assert not any(f.category.value == "cdn-reference" for f in findings)
