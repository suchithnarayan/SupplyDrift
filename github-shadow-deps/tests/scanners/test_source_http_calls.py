"""Tests for SourceHTTPCallScanner."""
from __future__ import annotations

from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.source_http_calls import SourceHTTPCallScanner


def scan(content: str, file_type: str = "source_code", name: str = "app.ts"):
    scanner = SourceHTTPCallScanner(Config())
    target = FileTarget(path=Path(name), rel_path=name, file_type=file_type)
    return scanner.scan_file_content(target, content, content.splitlines())


def test_detects_external_url_constant_used_by_fetch():
    findings = scan(
        "const TWEMOJI_BASE = 'https://cdn.jsdelivr.net/gh/twitter/twemoji@latest/assets/svg';\n"
        "await fetch(`${TWEMOJI_BASE}/1f91d.svg`);\n"
    )

    assert any(
        f.pattern_id == "js-fetch-const-external"
        and f.extracted_dep == "https://cdn.jsdelivr.net/gh/twitter/twemoji@latest/assets/svg"
        for f in findings
    )


def test_detects_external_url_constant_used_by_axios():
    findings = scan(
        "const url = `https://api.figma.com/v1/files/${fileKey}`;\n"
        "const response = await axios.get(url, { headers });\n",
        name="bdd_ai_toolkit/src/tools/figmaExtractor.ts",
    )

    assert any(
        f.pattern_id == "js-fetch-const-external"
        and f.extracted_dep == "https://api.figma.com/v1/files/${fileKey}"
        for f in findings
    )


def test_detects_concatenated_external_url_constant_used_by_fetch():
    findings = scan(
        'let url = "https://js.monitor.azure.com/scripts/b/ai." + version + ".js";\n'
        "const res = await fetch(encodeURI(url));\n",
        name="tools/sizeImageGenerator/size-image-generator.js",
    )

    assert any(
        f.pattern_id == "js-fetch-const-external"
        and f.extracted_dep == "https://js.monitor.azure.com/scripts/b/ai.${version}.js"
        for f in findings
    )
    assert not any(
        f.pattern_id == "js-fetch-const-external"
        and f.extracted_dep == "https://js.monitor.azure.com/scripts/b/ai."
        for f in findings
    )


def test_detects_multiline_external_url_constant_used_by_fetch():
    findings = scan(
        "function fetchCanary() {\n"
        "  const rnwNuGetFeed =\n"
        '    "https://pkgs.dev.azure.com/ms/react-native/_packaging/react-native-public/nuget/v3/index.json";\n'
        "  return fetch(rnwNuGetFeed).then((res) => res.json());\n"
        "}\n",
        name="packages/app/scripts/internal/set-react-version.mts",
    )

    assert any(
        f.pattern_id == "js-fetch-const-external"
        and f.extracted_dep == "https://pkgs.dev.azure.com/ms/react-native/_packaging/react-native-public/nuget/v3/index.json"
        for f in findings
    )


def test_url_constant_scope_does_not_leak_across_functions():
    findings = scan(
        "function fetchTemplateManifest(version) {\n"
        "  const url =\n"
        "    `https://raw.githubusercontent.com/react-native-community/template/refs/heads/${version}-stable/template/package.json`;\n"
        "  return fetch(url);\n"
        "}\n"
        "function fetchReactNativeWindowsCanaryInfoViaNuGet() {\n"
        "  const rnwNuGetFeed =\n"
        '    "https://pkgs.dev.azure.com/ms/react-native/_packaging/react-native-public/nuget/v3/index.json";\n'
        "  return fetch(rnwNuGetFeed)\n"
        "    .then((url) => fetch(url + '/Microsoft.ReactNative.Cxx/index.json'));\n"
        "}\n",
        name="packages/app/scripts/internal/set-react-version.mts",
    )

    assert any(
        f.pattern_id == "js-fetch-const-external"
        and f.extracted_dep == "https://raw.githubusercontent.com/react-native-community/template/refs/heads/${version}-stable/template/package.json"
        for f in findings
    )
    assert any(
        f.pattern_id == "js-fetch-const-external"
        and f.extracted_dep == "https://pkgs.dev.azure.com/ms/react-native/_packaging/react-native-public/nuget/v3/index.json"
        for f in findings
    )
    assert not any(
        f.pattern_id == "js-fetch-const-external"
        and f.line_number == 10
        and f.extracted_dep == "https://raw.githubusercontent.com/react-native-community/template/refs/heads/${version}-stable/template/package.json"
        for f in findings
    )


def test_ignores_fetch_function_declaration_with_url_parameter():
    findings = scan(
        "async function vendorOne(target) {\n"
        "  const url = `https://openpolicyagent.org/downloads/v${VERSION}/${target.asset}`;\n"
        "  return fetchWithRetry(url);\n"
        "}\n"
        "function fetch(url, redirectsLeft = 5) {\n"
        "  return new Promise((resolve) => resolve(url));\n"
        "}\n",
        name="policy-engine/sdk/node/scripts/fetch-opa.mjs",
    )

    assert not any(
        f.pattern_id == "js-fetch-const-external"
        and f.line_number == 5
        for f in findings
    )


def test_callback_parameter_shadows_url_constant():
    findings = scan(
        "function loadAll(urls) {\n"
        "  const url = 'https://api.example.com/base';\n"
        "  return urls.map((url) => fetch(url));\n"
        "}\n"
    )

    assert findings == []


def test_ignores_unused_external_url_constant():
    findings = scan(
        "const BASE = 'https://cdn.jsdelivr.net/npm/tool@latest/index.js';\n"
        "console.log(BASE);\n"
    )

    assert not any(f.pattern_id == "js-fetch-const-external" for f in findings)


def test_ignores_external_url_constant_used_by_git_fetch_method():
    findings = scan(
        "const RN_GITHUB_URL = 'https://github.com/react/react-native.git';\n"
        "await this.gitClient.fetch([RN_GITHUB_URL, gitRef, '--depth=1']);\n",
        name="packages/react-native-platform-override/src/GitReactFileRepository.ts",
    )

    assert not any(
        f.pattern_id == "js-fetch-const-external"
        and f.extracted_dep == "https://github.com/react/react-native.git"
        for f in findings
    )


def test_ignores_localhost_url_constant_used_by_fetch():
    findings = scan(
        "const BASE = 'http://localhost:3000/api';\n"
        "await fetch(`${BASE}/health`);\n"
    )

    assert findings == []


def test_ignores_external_fetch_in_test_source_path():
    findings = scan(
        'const a = web.fetch("https://a.com");\n',
        name="packages/workflow/test/compiler.spec.ts",
    )

    assert findings == []


def test_ignores_external_fetch_in_camelcase_test_source_filename():
    findings = scan(
        "const url = `https://geocoding-api.open-meteo.com/v1/search?name=${encodedLocation}&count=1&language=en&format=json`;\n"
        "await fetch(url);\n",
        name="ts/packages/agents/weather/testWeatherSimple.mjs",
    )

    assert findings == []


def test_keeps_external_fetch_in_non_test_source_filename_starting_with_test():
    findings = scan(
        'fetch("https://api.example.com/testimonials");\n',
        name="src/testimonials.ts",
    )

    assert any(
        f.pattern_id == "js-fetch-external"
        and f.extracted_dep == "https://api.example.com/testimonials"
        for f in findings
    )


def test_ignores_template_placeholder_host_fetch():
    findings = scan(
        "await fetch(`https://${url}/data.json`);\n",
        name="src/batchWorker.ts",
    )

    assert findings == []


def test_ignores_template_placeholder_host_constant_fetch():
    findings = scan(
        "const url = `https://${flags.aswaHostname}/data/${otherFile}`;\n"
        "await fetch(url);\n",
        name="src/deploy.ts",
    )

    assert findings == []


def test_keeps_concrete_host_with_template_path_fetch():
    findings = scan(
        "const url = `https://api.github.com/repos/${owner}/${repo}/pulls`;\n"
        "await fetch(url);\n",
        name="src/githubApiClient.ts",
    )

    assert any(
        f.pattern_id == "js-fetch-const-external"
        and f.extracted_dep == "https://api.github.com/repos/${owner}/${repo}/pulls"
        for f in findings
    )


def test_ignores_external_fetch_in_testdata_baseline_path():
    findings = scan(
        "const baseUrl = 'https://api.publicapis.org/';\n"
        "return fetch(baseUrl + 'entries')\n",
        name="testdata/baselines/reference/compiler/output.js",
    )

    assert findings == []


def test_ignores_reserved_example_url_in_example_source_path():
    findings = scan(
        'fetch("https://api.example.com/data", { method: "POST" });\n',
        name="examples/dependency/src/startSpan-example.ts",
    )

    assert findings == []


def test_ignores_jsonplaceholder_url_in_sample_source_path():
    findings = scan(
        'axios.get("https://jsonplaceholder.typicode.com/users").then((res) => res.data);\n',
        name="samples/spa/vue/vue-admin-template/src/users.js",
    )

    assert findings == []


def test_keeps_jsonplaceholder_url_in_non_sample_source_path():
    findings = scan(
        'axios.get("https://jsonplaceholder.typicode.com/users").then((res) => res.data);\n',
        name="src/users.js",
    )

    assert any(
        f.pattern_id == "js-axios-external"
        and f.extracted_dep == "https://jsonplaceholder.typicode.com/users"
        for f in findings
    )


def test_keeps_real_external_url_in_example_source_path():
    findings = scan(
        'fetch("https://api.github.com/repos/microsoft/typespec", { method: "GET" });\n',
        name="examples/dependency/src/startSpan-example.ts",
    )

    assert any(
        f.pattern_id == "js-fetch-external"
        and f.extracted_dep == "https://api.github.com/repos/microsoft/typespec"
        for f in findings
    )


def test_ignores_commented_external_fetches():
    findings = scan(
        "// const response = await fetch(`https://index.commoncrawl.org/search?q=x`);\n"
        "// const BASE = 'https://cdn.jsdelivr.net/npm/tool/index.js';\n"
        "// await fetch(`${BASE}/asset.js`);\n"
    )

    assert findings == []


def test_ignores_vendored_yarn_release_bundle_fetches():
    findings = scan(
        "const DATADOGH = 'https://browser-http-intake.logs.datadoghq.eu/v1/input/${e}?ddsource=yarn';\n"
        "await fetch(DATADOGH);\n",
        name=".yarn/releases/yarn-4.10.3.cjs",
    )

    assert findings == []


def test_ignores_external_url_constant_in_minified_bundle_line():
    findings = scan(
        "var NS='http://www.w3.org/2001/XMLSchema-instance';"
        + ("function n(){return 1};" * 80)
        + "fetch(NS);\n",
        name="static/js/openlayers/ol.js",
    )

    assert not any(f.pattern_id == "js-fetch-const-external" for f in findings)


def test_detects_direct_external_fetch_in_minified_bundle_line():
    findings = scan(
        "var x=1;"
        + ("function n(){return 1};" * 80)
        + "fetch('https://epsg.io/3857.proj4');\n",
        name="static/js/openlayers/ol.js",
    )

    assert any(
        f.pattern_id == "js-fetch-external"
        and f.extracted_dep == "https://epsg.io/3857.proj4"
        for f in findings
    )


def test_ignores_python_http_snippet_embedded_in_typescript_prompt_data():
    findings = scan(
        "export const cookbook = {\n"
        "  S113: 'Before: ```python import requests; requests.get(\"https://www.example.com/\") ```',\n"
        "  ASYNC210: 'Before: ```python urllib.request.urlopen(\"https://example.com/foo/bar\") ```',\n"
        "};\n",
        name="extensions/copilot/src/extension/prompts/node/inline/pythonCookbookData.ts",
    )

    assert not any(f.pattern_id.startswith("python-") for f in findings)


def test_detects_python_requests_in_python_source():
    findings = scan(
        "import requests\n"
        "response = requests.get('https://api.example.com/releases', timeout=10)\n",
        name="tools/create_release.py",
    )

    assert any(
        f.pattern_id == "python-requests-external"
        and f.extracted_dep == "https://api.example.com/releases"
        for f in findings
    )
