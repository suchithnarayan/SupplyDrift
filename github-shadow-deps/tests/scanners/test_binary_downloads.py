"""Tests for BinaryDownloadScanner."""
from __future__ import annotations

import tempfile
import warnings
from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.binary_downloads import BinaryDownloadScanner


def scan(content: str, file_type: str = "script", suffix: str = ".sh", name: str | None = None):
    scanner = BinaryDownloadScanner(Config())
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / (name or f"test{suffix}")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        target = FileTarget(path=p, rel_path=name or p.name, file_type=file_type)
        return scanner.scan_file(target)


def test_python_source_invalid_escape_does_not_emit_syntax_warning():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        findings = scan(
            'import subprocess\n'
            'pattern = "\\w+"\n'
            'subprocess.run(["curl", "-L", "https://example.com/tool.tar.gz", "-o", "tool.tar.gz"])\n',
            file_type="source_code",
            suffix=".py",
            name="tools/download.py",
        )

    assert not any(issubclass(warning.category, SyntaxWarning) for warning in caught)
    assert any(
        f.pattern_id == "curl-download-url-first"
        and f.extracted_dep == "https://example.com/tool.tar.gz"
        for f in findings
    )


def test_detects_wget_variable_download():
    findings = scan('wget -O /tmp/binary "$BASE_URL/tool-linux-amd64"\n')
    assert any(
        f.pattern_id == "wget-var-download"
        and f.extracted_dep == "$BASE_URL/tool-linux-amd64"
        for f in findings
    )


def test_detects_wget_variable_download_before_output_flag():
    findings = scan('wget $QUIET "$wrapperUrl" -O "$wrapperJarPath"\n')

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "wget-var-download"
    }
    assert "$wrapperUrl" in deps
    assert "$wrapperJarPath" not in deps


def test_detects_wget_dockerfile_env_variable_download_without_output_flag():
    findings = scan(
        "ENV AIRSIM_BINARY_ZIP_URL=https://github.com/microsoft/AirSim/releases/download/v1.3.1-linux/Blocks.zip\n"
        "RUN wget -c $AIRSIM_BINARY_ZIP_URL\n"
        "RUN unzip Blocks.zip\n",
        file_type="dockerfile",
        suffix="Dockerfile",
        name="Dockerfile",
    )

    assert any(
        f.pattern_id == "wget-var-download"
        and f.extracted_dep == "https://github.com/microsoft/AirSim/releases/download/v1.3.1-linux/Blocks.zip"
        and f.line_number == 2
        for f in findings
    )


def test_wget_preserves_shell_parameter_expansion_with_quotes():
    url = "https://repo1.maven.org/maven2/com/thoughtworks/qdox/qdox/${version/'~'/'-'}/${name}-${version/'~'/'-'}-project.tar.gz"
    findings = scan('wget "' + url + '" -O "${name}-${version}.orig.tar.gz"\n')

    assert any(
        f.pattern_id == "wget-download"
        and f.extracted_dep == url
        for f in findings
    )


def test_detects_curl_variable_download_after_output_flag():
    findings = scan(
        "curl.exe --location --fail --show-error --connect-timeout 30 "
        "--max-time 300 -o $DestinationPath $Url\n"
    )

    assert any(
        f.pattern_id == "curl-var-download" and f.extracted_dep == "$Url"
        for f in findings
    )


def test_curl_variable_download_ignores_options_variable_before_output_url():
    findings = scan(
        'curl_output=$(curl $curl_options -o "$out_path" '
        '"$remote_path_with_credential" 2>&1)\n'
    )

    assert not any(
        f.pattern_id == "curl-var-download" and f.extracted_dep == "$curl_options"
        for f in findings
    )


def test_download_helper_ignores_powershell_comment_help_examples():
    findings = scan(
        "<#\n"
        ".EXAMPLE\n"
        '    .\\Get-VerifiedDownload.ps1 -Url "https://example.com/tool.tar.gz" '
        '-ExpectedSHA256 "abc123..." -OutputPath "./tool.tar.gz"\n'
        "#>\n"
        "\n"
        'Write-Host "ready"\n',
        suffix=".ps1",
    )

    assert not any(f.pattern_id == "download-helper-url" for f in findings)


def test_download_helper_detects_active_powershell_invocation():
    findings = scan(
        '& "$PSScriptRoot\\Download-AndVerify.ps1" '
        '-Url "https://download.sysinternals.com/files/Procdump.zip" '
        "-DestinationPath $procDumpZipPath -ExpectedHash $env:PROCDUMP_EXPECTED_HASH\n",
        suffix=".ps1",
    )

    assert any(
        f.pattern_id == "download-helper-url"
        and f.extracted_dep == "https://download.sysinternals.com/files/Procdump.zip"
        for f in findings
    )


def test_ignores_powershell_hashtable_download_metadata_strings():
    findings = scan(
        "$ShellScriptPatterns = @{\n"
        "    'curl.*https://sh.rustup.rs' = @{\n"
        "        'Original' = 'curl --proto ''=https'' --tlsv1.2 -sSf https://sh.rustup.rs'\n"
        "        'Secure' = 'curl --proto ''=https'' --tlsv1.2 -sSf https://sh.rustup.rs | sha256sum -c <(echo \"abc  -\")'\n"
        "    }\n"
        "}\n",
        suffix=".ps1",
    )

    assert not any(
        f.pattern_id == "curl-download"
        and f.extracted_dep == "https://sh.rustup.rs"
        for f in findings
    )


def test_detects_active_powershell_curl_download():
    findings = scan(
        "curl -Lo tool.tar.gz https://github.com/example/tool/releases/download/v1.2.3/tool.tar.gz\n",
        suffix=".ps1",
    )

    assert any(
        f.pattern_id == "curl-download"
        and f.extracted_dep == "https://github.com/example/tool/releases/download/v1.2.3/tool.tar.gz"
        for f in findings
    )


def test_detects_powershell_invoke_webrequest_binary_download():
    findings = scan(
        'Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Procdump.zip" '
        "-OutFile $procDumpZipPath -UseBasicParsing\n",
        suffix=".ps1",
    )

    assert any(
        f.pattern_id == "powershell-invoke-webrequest"
        and f.extracted_dep == "https://download.sysinternals.com/files/Procdump.zip"
        for f in findings
    )


def test_detects_powershell_invoke_webrequest_literal_with_options_before_outfile():
    findings = scan(
        'Invoke-WebRequest "https://netcorenativeassets.blob.core.windows.net/resource-packages/external/windows/vswhere/$vswhereVersion/vswhere.exe" '
        "-UseBasicParsing -OutFile $vswhereExe\n",
        suffix=".ps1",
        name="eng/common/tools.ps1",
    )

    assert any(
        f.pattern_id == "powershell-invoke-webrequest"
        and f.extracted_dep
        == "https://netcorenativeassets.blob.core.windows.net/resource-packages/external/windows/vswhere/$vswhereVersion/vswhere.exe"
        for f in findings
    )


def test_detects_powershell_invoke_webrequest_literal_across_backtick_continuation():
    findings = scan(
        "Invoke-WebRequest 'https://github.com/microsoft/WinAppDriver/releases/download/v1.2.1/WindowsApplicationDriver_1.2.1.msi' `\n"
        "  -OutFile (New-Item -Path '${{ github.workspace }}/download2/wad.msi' -Force)\n",
        file_type="ci",
        suffix=".yml",
        name=".github/workflows/action-ci.yml",
    )

    assert any(
        f.pattern_id == "powershell-invoke-webrequest"
        and f.extracted_dep
        == "https://github.com/microsoft/WinAppDriver/releases/download/v1.2.1/WindowsApplicationDriver_1.2.1.msi"
        and f.line_number == 1
        for f in findings
    )


def test_detects_powershell_invoke_webrequest_retry_wrapper_literal_download():
    findings = scan(
        'Invoke-WebRequest-WithRetry -Uri "https://aka.ms/vs/17/release/vc_redist.$Platform.exe" '
        '-OutFile "$ArtifactsDir\\vc_redist.$Platform.exe"\n',
        suffix=".ps1",
        name="tools/prepare-machine.ps1",
    )

    assert any(
        f.pattern_id == "powershell-invoke-webrequest"
        and f.extracted_dep == "https://aka.ms/vs/17/release/vc_redist.$Platform.exe"
        for f in findings
    )


def test_detects_powershell_invoke_webrequest_variable_binary_url():
    findings = scan(
        '$pythonUrl = "https://www.python.org/ftp/python/$pythonFullVersion/python-$pythonFullVersion-amd64.exe"\n'
        '$installerPath = "$env:TEMP\\python-$pythonFullVersion-amd64.exe"\n'
        "Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath -UseBasicParsing\n",
        suffix=".ps1",
    )

    assert any(
        f.pattern_id == "powershell-invoke-webrequest"
        and f.extracted_dep == "https://www.python.org/ftp/python/$pythonFullVersion/python-$pythonFullVersion-amd64.exe"
        for f in findings
    )


def test_detects_powershell_webclient_variable_binary_url():
    findings = scan(
        '$airSimBinaryZipUrl = "https://github.com/microsoft/AirSim/releases/download/v1.3.1-windows/Blocks.zip"\n'
        "$webClient.DownloadFile($airSimBinaryZipUrl, $airSimInstallPath + $airSimBinaryZipFilename)\n",
        suffix=".ps1",
    )

    assert any(
        f.pattern_id == "powershell-webclient-download"
        and f.extracted_dep == "https://github.com/microsoft/AirSim/releases/download/v1.3.1-windows/Blocks.zip"
        for f in findings
    )


def test_detects_powershell_local_download_helper_literal_binary_url():
    findings = scan(
        "function download($url, $path) {\n"
        "  $wc = New-Object System.Net.WebClient\n"
        "  $wc.DownloadFile($url, $path)\n"
        "}\n"
        "download https://github.com/microsoft/vcpkg-tool/releases/latest/download/vcpkg.exe $VCPKG\n",
        suffix=".ps1",
    )

    assert any(
        f.pattern_id == "powershell-download-helper-url"
        and f.extracted_dep == "https://github.com/microsoft/vcpkg-tool/releases/latest/download/vcpkg.exe"
        for f in findings
    )


def test_detects_powershell_download_helper_with_next_line_brace_and_named_uri():
    url = "https://download.visualstudio.microsoft.com/download/pr/ecb3860e/vs_BuildTools.exe"
    findings = scan(
        "function Download([uri]$Uri, [string]$OutFile)\n"
        "{\n"
        "  Invoke-WebRequest -Uri $Uri -OutFile $OutFile\n"
        "}\n"
        f"Download -Uri {url} -OutFile $vs_buildtools\n",
        suffix=".ps1",
    )

    assert any(
        f.pattern_id == "powershell-download-helper-url"
        and f.extracted_dep == url
        for f in findings
    )


def test_detects_powershell_download_from_helper_returned_binary_urls():
    findings = scan(
        "function Get-URLRewriteLink {\n"
        "  $DownloadLinks = @{\n"
        '    "x86" = @{ "en-US" = "https://download.microsoft.com/download/D/8/1/rewrite_x86_en-US.msi" }\n'
        '    "x64" = @{ "en-US" = "https://download.microsoft.com/download/1/2/8/rewrite_amd64_en-US.msi" }\n'
        "  }\n"
        '  return $DownloadLinks["x64"]["en-US"]\n'
        "}\n"
        "$DownloadLink = Get-URLRewriteLink\n"
        "$response = Invoke-WebRequest $DownloadLink -UseBasicParsing\n",
        suffix=".ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "powershell-invoke-webrequest"
    }
    assert deps == {
        "https://download.microsoft.com/download/D/8/1/rewrite_x86_en-US.msi",
        "https://download.microsoft.com/download/1/2/8/rewrite_amd64_en-US.msi",
    }


def test_ignores_powershell_helper_returned_binary_url_without_download_sink():
    findings = scan(
        "function Get-InstallerLink {\n"
        '  return "https://download.example.com/tool.msi"\n'
        "}\n"
        "$DownloadLink = Get-InstallerLink\n"
        "Write-Host $DownloadLink\n",
        suffix=".ps1",
    )

    assert not any(
        f.pattern_id == "powershell-invoke-webrequest"
        and f.extracted_dep == "https://download.example.com/tool.msi"
        for f in findings
    )


def test_powershell_variable_binary_download_ignores_text_metadata_url():
    findings = scan(
        '$checksumsUrl = "https://github.com/org/tool/releases/download/v1.2.3/checksums.txt"\n'
        "Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumsPath -UseBasicParsing\n"
        "$client.DownloadFile($checksumsUrl, $checksumsPath)\n",
        suffix=".ps1",
    )

    assert not any(
        f.extracted_dep == "https://github.com/org/tool/releases/download/v1.2.3/checksums.txt"
        for f in findings
    )


def test_detects_powershell_start_bits_transfer_variable_binary_url():
    findings = scan(
        '$PackageURL = "https://csuavsmicrohack.blob.core.windows.net/csuavsmicrohack/avs-embedded-labs-auto.zip"\n'
        "Start-BitsTransfer -Source $PackageURL -Destination $TempPath -Priority High\n"
        '$HcxPackageURL = "https://csuavsmicrohack.blob.core.windows.net/csuavsmicrohack/VMware-HCX-Connector.ova"\n'
        "Start-BitsTransfer -Source $HcxPackageURL -Destination $TempPath -Priority High\n",
        suffix=".ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "powershell-bits-transfer"
    }
    assert deps == {
        "https://csuavsmicrohack.blob.core.windows.net/csuavsmicrohack/avs-embedded-labs-auto.zip",
        "https://csuavsmicrohack.blob.core.windows.net/csuavsmicrohack/VMware-HCX-Connector.ova",
    }


def test_powershell_start_bits_transfer_ignores_variable_metadata_url():
    findings = scan(
        '$ReleaseUrl = "https://api.github.com/repos/acme/tool/releases/latest"\n'
        "Start-BitsTransfer -Source $ReleaseUrl -Destination $TempPath -Priority High\n",
        suffix=".ps1",
    )

    assert not any(f.pattern_id == "powershell-bits-transfer" for f in findings)


def test_detects_powershell_wrapper_literal_release_download():
    findings = scan(
        '$Notes = "Script can be downloaded here: https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName"\n'
        'Invoke-WebRequestWithProxyDetection -Uri "https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName" -OutFile $tempFullName\n',
        suffix=".ps1",
    )

    matches = [
        f for f in findings
        if f.pattern_id == "powershell-invoke-webrequest"
    ]
    assert len(matches) == 1
    assert matches[0].line_number == 2
    assert matches[0].extracted_dep == "https://github.com/microsoft/CSS-Exchange/releases/latest/download/$scriptName"


def test_detects_powershell_dynamic_github_release_asset_download_to_archive():
    findings = scan(
        '$url = "https://api.github.com/repos/microsoft/axe-windows/releases/latest"\n'
        "$response = Invoke-RestMethod -Uri $url -Method Get\n"
        '$asset = $response.assets | Where-Object { $_.name -like "*CLI*.zip" } | Select-Object -First 1\n'
        'Invoke-WebRequest -Uri $asset.browser_download_url -OutFile "AxeWindowsCLI.zip" -ErrorAction Stop\n'
        'Expand-Archive "AxeWindowsCLI.zip" -DestinationPath "AxeWindowsCLI" -Force\n',
        file_type="ci",
        suffix=".yml",
        name=".github/workflows/build.yml",
    )

    assert any(
        f.pattern_id == "powershell-dynamic-asset-download"
        and f.extracted_dep == "$asset.browser_download_url"
        for f in findings
    )


def test_detects_powershell_dynamic_release_asset_download_to_archive_variable():
    findings = scan(
        '$ArchiveFilePath = Join-Path -Path $TempFolderPath -ChildPath "vale.zip"\n'
        '$PackageAsset = $Release.Assets | Where-Object -Property name -Match $PackageNamePattern\n'
        "Invoke-WebRequest -Uri $PackageAsset.browser_download_url -OutFile $ArchiveFilePath -Verbose:$false\n",
        suffix=".ps1",
    )

    assert any(
        f.pattern_id == "powershell-dynamic-asset-download"
        and f.extracted_dep == "$packageasset.browser_download_url"
        for f in findings
    )


def test_detects_powershell_dynamic_actions_artifact_archive_download():
    findings = scan(
        '$zipPath = "$downloadDir.zip"\n'
        "Invoke-WebRequest -Uri $artifact.archive_download_url -OutFile $zipPath -Headers $headers -UseBasicParsing\n",
        file_type="ci",
        suffix=".yml",
        name=".github/workflows/e2e.yml",
    )

    assert any(
        f.pattern_id == "powershell-dynamic-asset-download"
        and f.extracted_dep == "$artifact.archive_download_url"
        for f in findings
    )


def test_ignores_powershell_dynamic_download_url_property_to_metadata_file():
    findings = scan(
        '$file = Invoke-RestMethod -Uri "https://api.github.com/repos/acme/tool/contents/manifest.json"\n'
        'Invoke-WebRequest -Uri $file.download_url -OutFile "manifest.json" -ErrorAction Stop\n',
        suffix=".ps1",
    )

    assert not any(f.pattern_id == "powershell-dynamic-asset-download" for f in findings)


def test_python_source_shell_detects_wget_download():
    findings = scan(
        "import os\n"
        "os.system(f\"wget -O {output_dir}/raw/abo-3dmodels.tar https://amazon-berkeley-objects.s3.amazonaws.com/archives/abo-3dmodels.tar\")\n",
        file_type="source_code",
        suffix=".py",
        name="dataset_toolkits/datasets/ABO.py",
    )

    assert any(
        f.pattern_id == "wget-download"
        and f.extracted_dep == "https://amazon-berkeley-objects.s3.amazonaws.com/archives/abo-3dmodels.tar"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_subprocess_split_detects_wget_directory_variable_download():
    findings = scan(
        "import subprocess\n"
        "def fetch_latest(url: str):\n"
        '    subprocess.Popen(f"wget -N {url} -P /tmp".split()).wait()\n',
        file_type="source_code",
        suffix=".py",
        name="tla/install_deps.py",
    )

    assert any(
        f.pattern_id == "wget-var-download"
        and f.extracted_dep == "$url"
        and f.line_number == 3
        for f in findings
    )


def test_python_source_detects_local_download_helper_literal_artifact_urls():
    findings = scan(
        "import subprocess\n"
        "def fetch_latest(url: str, dest: str = '.'):\n"
        '    subprocess.Popen(f"wget -N {url} -P /tmp".split()).wait()\n'
        "fetch_latest(\n"
        '    url="https://github.com/informalsystems/apalache/releases/latest/download/apalache.tgz",\n'
        '    dest="tools",\n'
        ")\n"
        "fetch_latest(\n"
        '    url="https://github.com/tlaplus/CommunityModules/releases/latest/download/CommunityModules-deps.jar",\n'
        '    dest=".",\n'
        ")\n",
        file_type="source_code",
        suffix=".py",
        name="tla/install_deps.py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "python-download-helper-url"
    }
    assert "https://github.com/informalsystems/apalache/releases/latest/download/apalache.tgz" in deps
    assert "https://github.com/tlaplus/CommunityModules/releases/latest/download/CommunityModules-deps.jar" in deps


def test_python_source_ignores_non_download_helper_literal_url():
    findings = scan(
        "def describe(url: str):\n"
        "    return {'url': url}\n"
        'describe(url="https://github.com/example/project/releases/download/v1.0/tool.zip")\n',
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "python-download-helper-url" for f in findings)


def test_wget_variable_download_to_directory_prefix():
    findings = scan('wget -N "$artifactUrl" -P /tmp\n')

    assert any(
        f.pattern_id == "wget-var-download"
        and f.extracted_dep == "$artifactUrl"
        for f in findings
    )


def test_python_source_detects_urlretrieve_constant_archive_download():
    findings = scan(
        'COCO_URL = "https://ultralytics.com/assets/coco128.zip"\n'
        'COCO_ZIP = "quantization_dataset/coco128.zip"\n'
        "urllib.request.urlretrieve(COCO_URL, COCO_ZIP, reporthook=_hook)\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "python-urlretrieve-download"
        and f.extracted_dep == "https://ultralytics.com/assets/coco128.zip"
        for f in findings
    )


def test_python_source_detects_urlretrieve_multiline_literal_archive_download():
    findings = scan(
        "def download(dataset_dir):\n"
        "    urllib.request.urlretrieve(\n"
        '        "https://mmlspark.blob.core.windows.net/publicwasb/17flowers.tgz",\n'
        '        dataset_dir + "17flowers.tgz",\n'
        "    )\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "python-urlretrieve-download"
        and f.extracted_dep == "https://mmlspark.blob.core.windows.net/publicwasb/17flowers.tgz"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_detects_urlretrieve_env_fallback_archive_download():
    findings = scan(
        '_DEFAULT_URL = "https://ndownloader.figshare.com/files/59468882"\n'
        'URL = os.environ.get("CHECKPOINT_URL", _DEFAULT_URL)\n'
        'ZIP_PATH = "/app/models/pistachio.zip"\n'
        "urllib.request.urlretrieve(URL, ZIP_PATH)\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "python-urlretrieve-download"
        and f.extracted_dep == "https://ndownloader.figshare.com/files/59468882"
        for f in findings
    )


def test_python_source_detects_urlretrieve_source_param_archive_download():
    findings = scan(
        "from urllib.request import urlretrieve\n"
        "def install_from_source(setuptools_source, pip_source):\n"
        "    setuptools_package, _ = urlretrieve(setuptools_source, 'setuptools.tar.gz')\n"
        "    pip_package, _ = urlretrieve(pip_source, 'pip.tar.gz')\n",
        file_type="source_code",
        suffix=".py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "python-urlretrieve-download"
    }
    assert "${setuptools_source}" in deps
    assert "${pip_source}" in deps


def test_python_source_ignores_urlretrieve_generic_path_archive_download():
    findings = scan(
        "from urllib.request import urlretrieve\n"
        "def copy(path):\n"
        "    return urlretrieve(path, 'archive.tar.gz')\n",
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "python-urlretrieve-download" for f in findings)


def test_python_source_detects_urlretrieve_multiline_concatenated_model_url():
    findings = scan(
        "def get_aesthetic_model(clip_model='vit_l_14'):\n"
        '    path_to_model = cache_folder + "/sa_0_4_"+clip_model+"_linear.pth"\n'
        "    url_model = (\n"
        '        "https://github.com/LAION-AI/aesthetic-predictor/blob/main/sa_0_4_"+clip_model+"_linear.pth?raw=true"\n'
        "    )\n"
        "    urlretrieve(url_model, path_to_model)\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "python-urlretrieve-download"
        and f.extracted_dep
        == "https://github.com/LAION-AI/aesthetic-predictor/blob/main/sa_0_4_${clip_model}_linear.pth?raw=true"
        and f.line_number == 6
        for f in findings
    )


def test_python_source_detects_wget_download_default_model_url():
    findings = scan(
        'def __init__(self, url="https://zenodo.org/records/18165116/files/herdnet_loc_branch_wildme.pth?download=1"):\n'
        "    weights = wget.download(url, out=os.path.join(torch.hub.get_dir(), 'checkpoints'))\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "python-wget-download"
        and f.extracted_dep == "https://zenodo.org/records/18165116/files/herdnet_loc_branch_wildme.pth?download=1"
        for f in findings
    )


def test_python_source_detects_wget_download_urlish_var_to_checkpoint_dir():
    findings = scan(
        "def _load_model(self, url=None):\n"
        "    if url:\n"
        '        os.makedirs(os.path.join(torch.hub.get_dir(), "checkpoints"), exist_ok=True)\n'
        '        weights = wget.download(url, out=os.path.join(torch.hub.get_dir(), "checkpoints"))\n',
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "python-wget-download"
        and f.extracted_dep == "${url}"
        and f.line_number == 4
        for f in findings
    )


def test_python_source_ignores_wget_download_metadata_url_to_checkpoint_dir():
    findings = scan(
        "def _load_cfg(self):\n"
        '    url = "https://zenodo.org/records/15178680/files/config_v9s.yaml?download=1"\n'
        '    return wget.download(url, out=os.path.join(torch.hub.get_dir(), "checkpoints"))\n',
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "python-wget-download" for f in findings)


def test_python_source_detects_wget_download_url_param_despite_metadata_url_in_other_function():
    findings = scan(
        "def _load_cfg(self):\n"
        '    url = "https://zenodo.org/records/15178680/files/config_v9s.yaml?download=1"\n'
        '    config_path = wget.download(url, out=os.path.join(torch.hub.get_dir(), "checkpoints"))\n'
        "def _load_model(self, weights=None, url=None):\n"
        "    if url:\n"
        '        weights = wget.download(url, out=os.path.join(torch.hub.get_dir(), "checkpoints"))\n',
        file_type="source_code",
        suffix=".py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "python-wget-download"
    }
    assert "${url}" in deps
    assert "https://zenodo.org/records/15178680/files/config_v9s.yaml?download=1" not in deps


def test_python_source_ignores_wget_download_urlish_var_without_binary_dest_hint():
    findings = scan(
        "def fetch(url, temp_dir):\n"
        "    return wget.download(url, out=temp_dir)\n",
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "python-wget-download" for f in findings)


def test_python_source_detects_super_init_forwarded_binary_url_variable():
    findings = scan(
        "class MegaDetectorV6Apache(RTDETRApacheBase):\n"
        "    def __init__(self, version='MDV6-apa-rtdetr-c'):\n"
        "        if version == 'MDV6-apa-rtdetr-c':\n"
        '            url = "https://zenodo.org/records/15398270/files/MDV6-apa-rtdetr-c.pth?download=1"\n'
        "        else:\n"
        '            url = "https://zenodo.org/records/15398270/files/MDV6-apa-rtdetr-e.pth?download=1"\n'
        "        super(MegaDetectorV6Apache, self).__init__(weights=None, device='cpu', url=url)\n",
        file_type="source_code",
        suffix=".py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "python-download-helper-url" and f.line_number == 7
    }
    assert deps == {
        "https://zenodo.org/records/15398270/files/MDV6-apa-rtdetr-c.pth?download=1",
        "https://zenodo.org/records/15398270/files/MDV6-apa-rtdetr-e.pth?download=1",
    }


def test_python_source_dedupes_forwarded_url_when_same_file_downloads_it():
    dep = "https://zenodo.org/records/18177050/files/HerdNet_Hybrid_Multiscale_Residual_wildme.pth?download=1"
    findings = scan(
        "class OWLT(Base):\n"
        f'    def __init__(self, weights=None, url="{dep}"):\n'
        "        super(OWLT, self).__init__(weights=weights, url=url)\n"
        "        self._load_model(weights, url)\n"
        "    def _load_model(self, weights=None, url=None):\n"
        "        if url:\n"
        '            weights = wget.download(url, out=os.path.join(torch.hub.get_dir(), "checkpoints"))\n',
        file_type="source_code",
        suffix=".py",
    )

    matching = [f for f in findings if f.extracted_dep == dep]
    assert [f.pattern_id for f in matching] == ["python-wget-download"]


def test_python_source_ignores_super_init_forwarded_non_binary_url_variable():
    findings = scan(
        "class Client(Base):\n"
        "    def __init__(self):\n"
        '        url = "https://api.github.com/repos/example/project/releases/latest"\n'
        "        super(Client, self).__init__(url=url)\n",
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "python-download-helper-url" for f in findings)


def test_python_source_detects_lisa_install_package_from_url_rpm():
    findings = scan(
        "class NvidiaCudaDriver:\n"
        "    def install(self):\n"
        "        package_url = (\n"
        '            "https://vault.centos.org/centos/7/os/x86_64/Packages/"\n'
        '            "vulkan-filesystem-1.1.97.0-1.el7.noarch.rpm"\n'
        "        )\n"
        "        self.node.os.install_package_from_url(package_url, signed=False)\n",
        file_type="source_code",
        suffix=".py",
        name="lisa/tools/gpu_drivers.py",
    )

    assert any(
        f.pattern_id == "python-package-url-install"
        and f.extracted_dep
        == "https://vault.centos.org/centos/7/os/x86_64/Packages/vulkan-filesystem-1.1.97.0-1.el7.noarch.rpm"
        and f.line_number == 7
        for f in findings
    )


def test_python_source_detects_lisa_install_package_from_url_in_truncated_source():
    findings = scan(
        "class NvidiaCudaDriver:\n"
        "    NVIDIA_CUDA_REPO_BASE_URL = (\n"
        '        "https://developer.download.nvidia.com/compute/cuda/repos"\n'
        "    )\n"
        "    def install(self, release):\n"
        "        cuda_keyring_url = (\n"
        "            f\"{self.NVIDIA_CUDA_REPO_BASE_URL}/\"\n"
        "            f\"ubuntu{release}/x86_64/cuda-keyring_1.0-1_all.deb\"\n"
        "        )\n"
        "        self.node.os.install_package_from_url(\n"
        "            cuda_keyring_url,\n"
        '            package_name="cuda-keyring.deb",\n'
        "            signed=False,\n"
        "        )\n"
        "unfinished = (\n",
        file_type="source_code",
        suffix=".py",
        name="lisa/tools/gpu_drivers.py",
    )

    assert any(
        f.pattern_id == "python-package-url-install"
        and f.extracted_dep
        == "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu${release}/x86_64/cuda-keyring_1.0-1_all.deb"
        and f.line_number == 10
        for f in findings
    )


def test_python_source_ignores_install_package_from_url_non_artifact_api_url():
    findings = scan(
        "def install(node):\n"
        "    node.os.install_package_from_url(\n"
        "        url='https://api.github.com/repos/acme/tool/releases/latest',\n"
        "        package_name='release.json',\n"
        "    )\n",
        file_type="source_code",
        suffix=".py",
        name="installer.py",
    )

    assert not any(f.pattern_id == "python-package-url-install" for f in findings)


def test_python_source_detects_lisa_wget_tool_get_executable_script():
    findings = scan(
        "from lisa.base_tools import Wget\n"
        "def install(self):\n"
        "    wget_tool = self.node.tools[Wget]\n"
        "    script_path = wget_tool.get(\n"
        '        "https://get.docker.com",\n'
        '        filename="get-docker.sh",\n'
        '        file_path="./",\n'
        "        executable=True,\n"
        "    )\n"
        '    self.node.execute(f"{script_path}", sudo=True)\n',
        file_type="source_code",
        suffix=".py",
        name="lisa/tools/docker.py",
    )

    assert any(
        f.pattern_id == "python-wget-tool-download"
        and f.extracted_dep == "https://get.docker.com"
        and f.line_number == 4
        for f in findings
    )


def test_python_source_detects_lisa_wget_tool_run_release_binary():
    findings = scan(
        "from lisa.base_tools import Wget\n"
        "def install(self, hardware):\n"
        "    wget_tool = self.node.tools[Wget]\n"
        "    filename = 'docker-compose'\n"
        "    wget_tool.run(\n"
        '        "https://github.com/docker/compose/releases/download/v2.14.2"\n'
        '        f"/docker-compose-Linux-{hardware} -O {filename}",\n'
        "        sudo=True,\n"
        "    )\n",
        file_type="source_code",
        suffix=".py",
        name="lisa/tools/docker_compose.py",
    )

    assert any(
        f.pattern_id == "python-wget-tool-download"
        and f.extracted_dep
        == "https://github.com/docker/compose/releases/download/v2.14.2/docker-compose-Linux-${hardware}"
        and f.line_number == 5
        for f in findings
    )


def test_python_source_detects_lisa_direct_wget_tool_get_tarball_variable():
    findings = scan(
        "from lisa.base_tools import Wget\n"
        "def install(node):\n"
        '    tar_file = "https://download.open-mpi.org/release/open-mpi/v4.1/openmpi-4.1.5.tar.gz"\n'
        "    tar_file_path = node.tools[Wget].get(tar_file, file_path='/tmp', executable=True)\n",
        file_type="source_code",
        suffix=".py",
        name="lisa/features/infiniband.py",
    )

    assert any(
        f.pattern_id == "python-wget-tool-download"
        and f.extracted_dep == "https://download.open-mpi.org/release/open-mpi/v4.1/openmpi-4.1.5.tar.gz"
        and f.line_number == 4
        for f in findings
    )


def test_python_source_detects_lisa_wget_tool_get_class_url_attribute():
    findings = scan(
        "from lisa.tools import Wget\n"
        "class Texinfo:\n"
        '    version = "7.0.1.90"\n'
        '    source_link = f"http://alpha.gnu.org/gnu/texinfo/texinfo-{version}.tar.xz"\n'
        "    def install(self):\n"
        "        wget = self.node.tools[Wget]\n"
        "        return wget.get(\n"
        "            url=self.source_link,\n"
        '            filename=f"texinfo-{self.version}.tar.xz",\n'
        "            file_path='/tmp',\n"
        "        )\n",
        file_type="source_code",
        suffix=".py",
        name="lisa/tools/texinfo.py",
    )

    assert any(
        f.pattern_id == "python-wget-tool-download"
        and f.extracted_dep == "http://alpha.gnu.org/gnu/texinfo/texinfo-7.0.1.90.tar.xz"
        and f.line_number == 7
        for f in findings
    )


def test_python_source_detects_lisa_wget_tool_in_truncated_source():
    findings = scan(
        "from lisa.base_tools import Wget\n"
        "class NvidiaGridDriver:\n"
        '    DEFAULT_GRID_DRIVER_URL = "https://go.microsoft.com/fwlink/?linkid=874272"\n'
        "    def install(self, driver_url=None):\n"
        "        if not driver_url:\n"
        "            driver_url = self.DEFAULT_GRID_DRIVER_URL\n"
        "        wget_tool = self.node.tools[Wget]\n"
        "        grid_file_path = wget_tool.get(\n"
        "            driver_url,\n"
        "            str(self.node.working_path),\n"
        '            "NVIDIA-Linux-x86_64-grid.run",\n'
        "            executable=True,\n"
        "        )\n"
        "unfinished = (\n",
        file_type="source_code",
        suffix=".py",
        name="lisa/tools/gpu_drivers.py",
    )

    assert any(
        f.pattern_id == "python-wget-tool-download"
        and f.extracted_dep == "https://go.microsoft.com/fwlink/?linkid=874272"
        and f.line_number == 8
        for f in findings
    )


def test_python_source_ignores_unrelated_client_get_binary_url():
    findings = scan(
        "def fetch(client):\n"
        "    return client.get('https://example.com/releases/download/v1/tool.tar.gz')\n",
        file_type="source_code",
        suffix=".py",
        name="client.py",
    )

    assert not any(f.pattern_id == "python-wget-tool-download" for f in findings)


def test_python_source_ignores_requests_get_json_api():
    findings = scan(
        'API_URL = "https://api.github.com/repos/example/project/releases/latest"\n'
        "response = requests.get(API_URL, stream=True, timeout=10)\n",
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "python-requests-stream-download" for f in findings)


def test_python_source_detects_requests_stream_plain_tar_archive_download():
    findings = scan(
        "import requests\n"
        'url = "https://storage.googleapis.com/alphafold/alphafold_params_2021-07-14.tar"\n'
        "response = requests.get(url, stream=True, timeout=60)\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "python-requests-stream-download"
        and f.extracted_dep == "https://storage.googleapis.com/alphafold/alphafold_params_2021-07-14.tar"
        and f.line_number == 3
        for f in findings
    )


def test_python_source_detects_requests_content_write_from_actions_archive_url():
    findings = scan(
        "import requests\n"
        "response = requests.get(\n"
        '    artifact["archive_download_url"], headers=headers)\n'
        "response.raise_for_status()\n"
        'with open("mainbranchcov.zip", "wb") as f:\n'
        "    f.write(response.content)\n",
        file_type="source_code",
        suffix=".py",
        name="scripts/coverage/get_coverage.py",
    )

    assert any(
        f.pattern_id == "python-requests-content-download"
        and "archive_download_url" in f.extracted_dep
        and f.line_number == 3
        for f in findings
    )


def test_python_source_detects_direct_requests_content_write_to_zip_path_variable():
    findings = scan(
        "import requests\n"
        "def download(destination_dir, package_name, version):\n"
        '    package_url = f"https://www.nuget.org/api/v2/package/{package_name}/{version}"\n'
        '    package_path = destination_dir / f"{package_name}.zip"\n'
        '    with open(package_path, "wb") as f:\n'
        "        f.write(requests.get(package_url).content)\n",
        file_type="source_code",
        suffix=".py",
        name="tools/python/util/dependency_resolver.py",
    )

    assert any(
        f.pattern_id == "python-requests-content-download"
        and f.extracted_dep == "https://www.nuget.org/api/v2/package/${package_name}/${version}"
        and f.line_number == 6
        for f in findings
    )


def test_python_source_detects_requests_content_write_bytes_from_zip_url_helper():
    findings = scan(
        "import requests\n"
        "def _get_dataset_url(dataset):\n"
        '    return f"https://raw.githubusercontent.com/microsoft/benchmark-qed/refs/heads/main/datasets/{dataset}/raw_data.zip"\n'
        "api_url = _get_dataset_url(dataset)\n"
        "response = requests.get(api_url, timeout=60)\n"
        'output_file = output_dir / f"{dataset}.zip"\n'
        "output_file.write_bytes(response.content)\n",
        file_type="source_code",
        suffix=".py",
        name="benchmark_qed/data/cli.py",
    )

    assert any(
        f.pattern_id == "python-requests-content-download"
        and f.extracted_dep == "_get_dataset_url(dataset)"
        and f.line_number == 5
        for f in findings
    )


def test_python_source_detects_streamed_requests_chunks_from_attribute_zip_url():
    findings = scan(
        "import requests\n"
        "class Converter:\n"
        '    DEFAULT_TSV_URL = "https://www.bindingdb.org/rwd/bind/downloads/BindingDB_All_202605_tsv.zip"\n'
        "    def __init__(self):\n"
        "        self.tsv_url = self.DEFAULT_TSV_URL\n"
        "    def download(self):\n"
        '        zip_path = "BindingDB_All.zip"\n'
        "        response = requests.get(self.tsv_url, stream=True, timeout=3600)\n"
        '        with open(zip_path, "wb") as f:\n'
        "            for chunk in response.iter_content(chunk_size=8192):\n"
        "                if chunk:\n"
        "                    f.write(chunk)\n",
        file_type="source_code",
        suffix=".py",
        name="agents/bindingdb/tools/BindingDB/tsv_to_sqlite.py",
    )

    assert any(
        f.pattern_id == "python-requests-content-download"
        and f.extracted_dep == "https://www.bindingdb.org/rwd/bind/downloads/BindingDB_All_202605_tsv.zip"
        and f.line_number == 8
        for f in findings
    )


def test_python_source_detects_context_managed_requests_stream_from_dynamic_download_url():
    findings = scan(
        "import requests\n"
        "def download(output_path, build_artifact):\n"
        "    download_url = build_artifact.resource.download_url\n"
        '    file_extension = "zip"\n'
        '    artifact_path = output_path / f"{build_artifact.name}.{file_extension}"\n'
        "    with requests.get(download_url, stream=True) as response:\n"
        '        with open(artifact_path, "wb") as f:\n'
        "            for chunk in response.iter_content(chunk_size=1024):\n"
        "                if chunk:\n"
        "                    f.write(chunk)\n",
        file_type="source_code",
        suffix=".py",
        name="lisa/advanced_tools/ado_artifact_download.py",
    )

    assert any(
        f.pattern_id == "python-requests-content-download"
        and f.extracted_dep == "build_artifact.resource.download_url"
        and f.line_number == 6
        for f in findings
    )


def test_python_source_detects_download_helper_writing_response_content_to_archive_arg():
    findings = scan(
        "import requests\n"
        "def run(host_url, ID, path):\n"
        "    def download(ID: str, path: str) -> None:\n"
        "        res = requests.get(f\"{host_url}/result/download/{ID}\", timeout=6.02)\n"
        '        with open(path, "wb") as out:\n'
        "            out.write(res.content)\n"
        '    tar_gz_file = f"{path}/out.tar.gz"\n'
        "    download(ID, tar_gz_file)\n",
        file_type="source_code",
        suffix=".py",
        name="src/bioemu/colabfold_inline/msa_client.py",
    )

    assert any(
        f.pattern_id == "python-requests-content-download"
        and f.extracted_dep == "f'{host_url}/result/download/{ID}'"
        and f.line_number == 8
        for f in findings
    )


def test_python_source_line_fallback_detects_streamed_requests_chunks_from_truncated_file():
    findings = scan(
        "import requests\n"
        "class Converter:\n"
        '    DEFAULT_TSV_URL = "https://www.bindingdb.org/rwd/bind/downloads/BindingDB_All_202605_tsv.zip"\n'
        "    def __init__(self):\n"
        "        self.tsv_url = self.DEFAULT_TSV_URL\n"
        "    def download(self):\n"
        '        zip_path = "BindingDB_All.zip"\n'
        "        response = requests.get(self.tsv_url, stream=True, timeout=3600)\n"
        '        with open(zip_path, "wb") as f:\n'
        "            for chunk in response.iter_content(chunk_size=8192):\n"
        "                if chunk:\n"
        "                    f.write(chunk)\n"
        "try:\n",
        file_type="source_code",
        suffix=".py",
        name="agents/bindingdb/tools/BindingDB/tsv_to_sqlite.py",
    )

    assert any(
        f.pattern_id == "python-requests-content-download"
        and f.extracted_dep == "https://www.bindingdb.org/rwd/bind/downloads/BindingDB_All_202605_tsv.zip"
        and f.line_number == 8
        for f in findings
    )


def test_python_source_ignores_requests_content_write_json_metadata():
    findings = scan(
        "import requests\n"
        "response = requests.get(\n"
        '    artifact["archive_download_url"], headers=headers)\n'
        'with open("artifact.json", "wb") as f:\n'
        "    f.write(response.content)\n",
        file_type="source_code",
        suffix=".py",
        name="scripts/coverage/get_metadata.py",
    )

    assert not any(f.pattern_id == "python-requests-content-download" for f in findings)


def test_python_source_detects_torch_model_download_literal_url():
    findings = scan(
        "from torch.hub import load_state_dict_from_url\n"
        "state = load_state_dict_from_url('https://github.com/acme/models/releases/download/v1/model.pth')\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "python-torch-model-download"
        and f.extracted_dep == "https://github.com/acme/models/releases/download/v1/model.pth"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_detects_torch_model_download_url_map():
    findings = scan(
        "donwload_url = {\n"
        "    18: 'https://github.com/lyuwenyu/storage/releases/download/v0.1/ResNet18_vd_pretrained_from_paddle.pth',\n"
        "    34: 'https://github.com/lyuwenyu/storage/releases/download/v0.1/ResNet34_vd_pretrained_from_paddle.pth',\n"
        "}\n"
        "state = torch.hub.load_state_dict_from_url(donwload_url[depth], map_location='cpu')\n",
        file_type="source_code",
        suffix=".py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "python-torch-model-download"
    }
    assert deps == {
        "https://github.com/lyuwenyu/storage/releases/download/v0.1/ResNet18_vd_pretrained_from_paddle.pth",
        "https://github.com/lyuwenyu/storage/releases/download/v0.1/ResNet34_vd_pretrained_from_paddle.pth",
    }


def test_python_source_detects_huggingface_literal_artifact_download():
    findings = scan(
        "from huggingface_hub import hf_hub_download\n"
        'pt_path = hf_hub_download("nateraw/fairface", "val.pt", repo_type="dataset")\n',
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-artifact-download"
        and f.extracted_dep == "huggingface://nateraw/fairface/val.pt"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_detects_huggingface_multiline_fstring_artifact_download():
    findings = scan(
        "from huggingface_hub import hf_hub_download\n"
        "def load(model_name):\n"
        "    ckpt_path = hf_hub_download(\n"
        "        repo_id=\"microsoft/bioemu\", filename=f\"checkpoints/{model_name}/checkpoint.ckpt\"\n"
        "    )\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-artifact-download"
        and f.extracted_dep == "huggingface://microsoft/bioemu/checkpoints/${model_name}/checkpoint.ckpt"
        and f.line_number == 3
        for f in findings
    )


def test_python_source_detects_huggingface_repo_constant_artifact_download():
    findings = scan(
        "REPO = \"microsoft/mattergen\"\n"
        "hf_hub_download(repo_id=REPO, filename=f\"checkpoints/{m}/checkpoints/last.ckpt\")\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-artifact-download"
        and f.extracted_dep == "huggingface://microsoft/mattergen/checkpoints/${m}/checkpoints/last.ckpt"
        for f in findings
    )


def test_python_source_detects_huggingface_dynamic_repo_binary_artifact_download():
    findings = scan(
        "from huggingface_hub import hf_hub_download\n"
        "def load(path):\n"
        "    path_parts = path.split('/')\n"
        "    repo_id = f'{path_parts[0]}/{path_parts[1]}'\n"
        "    model_name = '/'.join(path_parts[2:])\n"
        "    config_file = hf_hub_download(repo_id, f\"{model_name}.json\")\n"
        "    model_file = hf_hub_download(repo_id, f\"{model_name}.safetensors\")\n",
        file_type="source_code",
        suffix=".py",
    )

    artifact_findings = [
        f for f in findings if f.pattern_id == "huggingface-artifact-download"
    ]
    assert any(
        f.extracted_dep == "huggingface://${path_parts[0]}/${path_parts[1]}/${model_name}.safetensors"
        and f.line_number == 7
        for f in artifact_findings
    )
    assert not any(f.extracted_dep.endswith(".json") for f in artifact_findings)


def test_python_source_ignores_huggingface_ambiguous_dynamic_repo_artifact_download():
    findings = scan(
        "from huggingface_hub import hf_hub_download\n"
        "def load(path):\n"
        "    return hf_hub_download(path, \"weights.safetensors\")\n",
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "huggingface-artifact-download" for f in findings)


def test_python_source_ignores_huggingface_config_download():
    findings = scan(
        "from huggingface_hub import hf_hub_download\n"
        "config_path = hf_hub_download(repo_id=\"microsoft/bioemu\", filename=\"checkpoints/main/config.yaml\")\n",
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "huggingface-artifact-download" for f in findings)


def test_python_source_detects_huggingface_load_attn_procs_weight_download():
    findings = scan(
        "def load(model):\n"
        '    model.load_attn_procs("lora-library/B-LoRA-pen_sketch", weight_name="pytorch_lora_weights.safetensors")\n',
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-artifact-download"
        and f.extracted_dep == "huggingface://lora-library/B-LoRA-pen_sketch/pytorch_lora_weights.safetensors"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_ignores_huggingface_load_attn_procs_non_binary_weight_name():
    findings = scan(
        "def load(model):\n"
        '    model.load_attn_procs("lora-library/B-LoRA-pen_sketch", weight_name="adapter_config.json")\n',
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "huggingface-artifact-download" for f in findings)


def test_python_source_detects_huggingface_snapshot_download_literal_repo():
    findings = scan(
        "from huggingface_hub import snapshot_download\n"
        "local_dir = snapshot_download(repo_id=\"gaia-benchmark/GAIA\", repo_type=\"dataset\")\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-snapshot-download"
        and f.extracted_dep == "huggingface://gaia-benchmark/GAIA/*"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_detects_huggingface_snapshot_download_repo_constant():
    findings = scan(
        "import huggingface_hub as hf_hub\n"
        "MODEL_ID = \"microsoft/Phi-3-mini-4k-instruct-onnx\"\n"
        "local_dir = hf_hub.snapshot_download(repo_id=MODEL_ID, allow_patterns=\"cpu_and_mobile/*\")\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-snapshot-download"
        and f.extracted_dep == "huggingface://microsoft/Phi-3-mini-4k-instruct-onnx/*"
        and f.line_number == 3
        for f in findings
    )


def test_python_source_ignores_huggingface_snapshot_runtime_repo():
    findings = scan(
        "from huggingface_hub import snapshot_download\n"
        "dataset_dir = snapshot_download(repo_id=dataset_repo_id, repo_type=\"dataset\")\n",
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "huggingface-snapshot-download" for f in findings)


def test_python_source_detects_huggingface_snapshot_in_truncated_source():
    findings = scan(
        "from huggingface_hub import snapshot_download\n"
        "local_dir = snapshot_download(\n"
        "    repo_id=\"gaia-benchmark/GAIA\",\n"
        "    repo_type=\"dataset\",\n"
        ")\n"
        "unfinished = (\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-snapshot-download"
        and f.extracted_dep == "huggingface://gaia-benchmark/GAIA/*"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_detects_huggingface_from_pretrained_literal_model():
    findings = scan(
        "from transformers import AutoImageProcessor\n"
        'processor = AutoImageProcessor.from_pretrained("google/vit-base-patch16-224", use_fast=True)\n',
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-from-pretrained-download"
        and f.extracted_dep == "huggingface://google/vit-base-patch16-224/*"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_detects_huggingface_from_pretrained_model_constant():
    findings = scan(
        "from transformers import AutoTokenizer\n"
        'MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"\n'
        "tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-from-pretrained-download"
        and f.extracted_dep == "huggingface://sentence-transformers/all-MiniLM-L6-v2/*"
        and f.line_number == 3
        for f in findings
    )


def test_python_source_detects_huggingface_from_pretrained_keyword_model_name():
    findings = scan(
        "from nemo.collections import asr as nemo_asr\n"
        'asr_model = nemo_asr.models.ASRModel.from_pretrained(model_name="nvidia/parakeet-tdt-0.6b-v2")\n',
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-from-pretrained-download"
        and f.extracted_dep == "huggingface://nvidia/parakeet-tdt-0.6b-v2/*"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_ignores_huggingface_from_pretrained_runtime_model_path():
    findings = scan(
        "from transformers import CLIPModel\n"
        "model_path = kwargs.get(\"model_path\")\n"
        "model = CLIPModel.from_pretrained(model_path)\n",
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "huggingface-from-pretrained-download" for f in findings)


def test_python_source_ignores_huggingface_from_pretrained_placeholder_repo():
    findings = scan(
        'runner = PolicyRunner.from_pretrained("test/repo", device="cuda")\n',
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "huggingface-from-pretrained-download" for f in findings)


def test_python_source_ignores_huggingface_from_pretrained_local_path_prefix():
    findings = scan(
        'model = AutoModel.from_pretrained("models/resnet")\n',
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "huggingface-from-pretrained-download" for f in findings)


def test_python_source_detects_huggingface_from_pretrained_in_truncated_source():
    findings = scan(
        "from transformers import AutoTokenizer\n"
        'tokenizer = AutoTokenizer.from_pretrained("microsoft/resnet-18")\n'
        "unfinished = (\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-from-pretrained-download"
        and f.extracted_dep == "huggingface://microsoft/resnet-18/*"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_ignores_huggingface_from_pretrained_docstring_in_truncated_source():
    findings = scan(
        '"""Usage:\n'
        'runner = PolicyRunner.from_pretrained("alizaidi/hve-robo-act-train", device="cuda")\n'
        '"""\n'
        "unfinished = (\n",
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "huggingface-from-pretrained-download" for f in findings)


def test_python_source_detects_huggingface_load_dataset_literal_repo():
    findings = scan(
        "from datasets import load_dataset\n"
        'dataset = load_dataset("sentence-transformers/stsb", split="test")\n',
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-dataset-load"
        and f.extracted_dep == "huggingface-dataset://sentence-transformers/stsb/*"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_detects_huggingface_load_dataset_module_qualified():
    findings = scan(
        "import datasets\n"
        'dataset = datasets.load_dataset("lmms-lab/ai2d", split="test")\n',
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-dataset-load"
        and f.extracted_dep == "huggingface-dataset://lmms-lab/ai2d/*"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_detects_huggingface_load_dataset_constant_repo():
    findings = scan(
        "from datasets import load_dataset\n"
        'DATASET_ID = "nielsr/coco-panoptic-val2017"\n'
        "dataset = load_dataset(DATASET_ID)\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-dataset-load"
        and f.extracted_dep == "huggingface-dataset://nielsr/coco-panoptic-val2017/*"
        and f.line_number == 3
        for f in findings
    )


def test_python_source_ignores_huggingface_load_dataset_builtin_dataset():
    findings = scan(
        "from datasets import load_dataset\n"
        'dataset = load_dataset("glue", "mrpc", split="train[:1%]")\n',
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "huggingface-dataset-load" for f in findings)


def test_python_source_ignores_huggingface_load_dataset_local_path_prefix():
    findings = scan(
        "from datasets import load_dataset\n"
        'dataset = load_dataset("data/training", split="train")\n',
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "huggingface-dataset-load" for f in findings)


def test_python_source_ignores_huggingface_load_dataset_runtime_name():
    findings = scan(
        "from datasets import load_dataset\n"
        "dataset = load_dataset(data_name, split=split)\n",
        file_type="source_code",
        suffix=".py",
    )

    assert not any(f.pattern_id == "huggingface-dataset-load" for f in findings)


def test_python_source_detects_huggingface_load_dataset_in_truncated_source():
    findings = scan(
        "from datasets import load_dataset\n"
        'dataset = load_dataset("microsoft/VISION_LANGUAGE", "maze_text_only", split="val")\n'
        "unfinished = (\n",
        file_type="source_code",
        suffix=".py",
    )

    assert any(
        f.pattern_id == "huggingface-dataset-load"
        and f.extracted_dep == "huggingface-dataset://microsoft/VISION_LANGUAGE/*"
        and f.line_number == 2
        for f in findings
    )


def test_dockerfile_detects_huggingface_from_pretrained_python_build_step():
    findings = scan(
        "FROM python:3.12\n"
        "RUN python -c \"from transformers import AutoModel; "
        "AutoModel.from_pretrained('InstaDeepAI/nucleotide-transformer-v2-500m-multi-species')\"\n",
        file_type="dockerfile",
        name="Dockerfile",
    )

    assert any(
        f.pattern_id == "huggingface-from-pretrained-download"
        and f.extracted_dep == "huggingface://InstaDeepAI/nucleotide-transformer-v2-500m-multi-species/*"
        and f.line_number == 2
        for f in findings
    )


def test_dockerfile_detects_huggingface_load_dataset_python_build_step():
    findings = scan(
        "FROM python:3.12\n"
        "RUN python -c \"from datasets import load_dataset; load_dataset('ai4privacy/pii-masking-200k', split='train')\"\n",
        file_type="dockerfile",
        name="Dockerfile",
    )

    assert any(
        f.pattern_id == "huggingface-dataset-load"
        and f.extracted_dep == "huggingface-dataset://ai4privacy/pii-masking-200k/*"
        and f.line_number == 2
        for f in findings
    )


def test_dockerfile_ignores_huggingface_local_or_builtin_loads():
    findings = scan(
        "FROM python:3.12\n"
        "RUN python -c \"AutoModel.from_pretrained('models/local'); load_dataset('glue', 'mrpc')\"\n",
        file_type="dockerfile",
        name="Dockerfile",
    )

    assert not any(
        f.pattern_id in {"huggingface-from-pretrained-download", "huggingface-dataset-load"}
        for f in findings
    )


def test_javascript_source_shell_detects_curl_download():
    findings = scan(
        "const cp = require('child_process');\n"
        "cp.execSync(`curl -L ${jacocoAgentUrl} -o ${jacocoAgentPath}`);\n",
        file_type="source_code",
        suffix=".js",
        name="scripts/buildJdtlsExt.js",
    )

    assert any(
        f.pattern_id == "curl-var-download"
        and f.extracted_dep == "${jacocoAgentUrl}"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_shell_detects_curl_argv_download():
    findings = scan(
        "import subprocess\n"
        'subprocess.run(["curl", "-L", "-o", temp_file, url_base + tar_file], check=True)\n',
        file_type="source_code",
        suffix=".py",
        name="prereqs.py",
    )

    assert any(
        f.pattern_id == "curl-var-download"
        and f.extracted_dep == "$url_base${tar_file}"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_shell_detects_wrapper_curl_argv_download_with_concatenated_arg():
    findings = scan(
        "def run(scenario):\n"
        "    scenario._call([\n"
        '        "curl",\n'
        '        " -L -o " + scenario.dut_exec_path + "/pugetbench.dmg "\n'
        '        "https://download.pugetsystems.com/pugetbench/pugetbench_creators/PugetBench%20for%20Creators_1.3.20_universal.dmg?submissionGuid=51975095-e8bb-45c0-8b1d-9d42a0c86bb8",\n'
        "    ])\n",
        file_type="source_code",
        suffix=".py",
        name="scenarios/macos/mac_puget_prep/code_16KJEV9.py",
    )

    assert any(
        f.pattern_id == "curl-download"
        and f.extracted_dep
        == "https://download.pugetsystems.com/pugetbench/pugetbench_creators/PugetBench%20for%20Creators_1.3.20_universal.dmg?submissionGuid=51975095-e8bb-45c0-8b1d-9d42a0c86bb8"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_shell_detects_runcmd_wget_download_with_fstring_url():
    findings = scan(
        "def build(work_dir, ver, pack_name):\n"
        '    ret = RunCmd("wget", f"https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v{ver}/{pack_name}.tar.gz", workingdir=work_dir)\n',
        file_type="source_code",
        suffix=".py",
        name="BaseTools/Edk2ToolsBuild.py",
    )

    assert any(
        f.pattern_id == "wget-download"
        and f.extracted_dep == "https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v$ver/$pack_name.tar.gz"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_shell_ignores_runcmd_non_download_command():
    findings = scan(
        "def build():\n"
        '    RunCmd("echo", "https://example.com/tool.tar.gz")\n',
        file_type="source_code",
        suffix=".py",
        name="build_tools.py",
    )

    assert not any(f.extracted_dep == "https://example.com/tool.tar.gz" for f in findings)


def test_python_source_shell_ignores_wrapper_non_command_argv_list():
    findings = scan(
        "def run(scenario):\n"
        '    scenario._call(["describe", "https://example.com/tool.zip"])\n',
        file_type="source_code",
        suffix=".py",
        name="scenarios/demo.py",
    )

    assert not any(f.extracted_dep == "https://example.com/tool.zip" for f in findings)


def test_javascript_source_shell_detects_curl_argv_download():
    findings = scan(
        "import { execFileSync } from 'child_process';\n"
        "execFileSync('curl', ['-sf', '-o', zip, url], { stdio: 'inherit' });\n",
        file_type="source_code",
        suffix=".mjs",
        name="utils/bisect-chromium.mjs",
    )

    assert any(
        f.pattern_id == "curl-var-download"
        and f.extracted_dep == "$url"
        and f.line_number == 2
        for f in findings
    )


def test_javascript_source_shell_binary_download_ignores_remote_script_pipe():
    findings = scan(
        "import { spawnSync } from 'child_process';\n"
        "spawnSync('bash', ['-c', 'wget -qO- https://gh.io/copilot-install | bash'], { stdio: 'inherit' });\n",
        file_type="source_code",
        suffix=".ts",
        name="extensions/copilot/src/extension/chatSessions/vscode-node/copilotCLIShim.ts",
    )

    assert not any(f.pattern_id == "wget-download" for f in findings)


def test_javascript_source_shell_detects_multiline_execsync_powershell_download():
    findings = scan(
        "const { execSync } = require('child_process');\n"
        "function ensureNuget(localNuGet) {\n"
        "  execSync(\n"
        "    `pwsh.exe -NoLogo -NoProfile -Command ` +\n"
        "      `\"[Net.ServicePointManager]::SecurityProtocol = ` +\n"
        "      `[Net.SecurityProtocolType]::Tls12; ` +\n"
        "      `Invoke-WebRequest -Uri 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe' ` +\n"
        "      `-OutFile '${localNuGet}' -UseBasicParsing\"`,\n"
        "    { stdio: 'inherit' },\n"
        "  );\n"
        "}\n",
        file_type="source_code",
        suffix=".js",
        name=".ado/scripts/build.js",
    )

    assert any(
        f.pattern_id == "powershell-invoke-webrequest"
        and f.extracted_dep == "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe"
        and f.line_number == 3
        for f in findings
    )


def test_javascript_source_embedded_archive_pipe_detects_returned_bootstrap_script():
    findings = scan(
        "export function compose(url: string, installRoot: string, cliBin: string): string {\n"
        "  const installLoose = `curl -fsSL ${shellEscape(url)} | tar xz -C ${installRoot} && chmod +x ${cliBin}`;\n"
        "  return [`if [ ! -x ${cliBin} ]; then ${installLoose}; fi`].join(' && ');\n"
        "}\n",
        file_type="source_code",
        suffix=".ts",
        name="src/vs/platform/agentHost/node/wslRemoteAgentHostHelpers.ts",
    )

    assert any(
        f.pattern_id == "archive-pipe-download"
        and f.extracted_dep == "${shellEscape(url)}"
        and f.line_number == 2
        for f in findings
    )


def test_javascript_source_embedded_archive_pipe_requires_urlish_template_expression():
    findings = scan(
        "export function compose(endpoint: string, installRoot: string): string {\n"
        "  return `curl -fsSL ${endpoint} | tar xz -C ${installRoot}`;\n"
        "}\n",
        file_type="source_code",
        suffix=".ts",
        name="src/compose.ts",
    )

    assert not any(f.pattern_id == "archive-pipe-download" for f in findings)


def test_javascript_source_embedded_archive_pipe_ignores_test_source_path():
    findings = scan(
        "it('documents installer command', () => {\n"
        "  const command = `curl -fsSL ${downloadUrl} | tar xz`;\n"
        "});\n",
        file_type="source_code",
        suffix=".ts",
        name="src/install.test.ts",
    )

    assert not any(f.pattern_id == "archive-pipe-download" for f in findings)


def test_devcontainer_lifecycle_command_detects_curl_binary_downloads():
    tflint_url = "https://github.com/terraform-linters/tflint/releases/download/${TFLINT_VERSION}/tflint_linux_${TFLINT_ARCH}.zip"
    ngc_url = "https://api.ngc.nvidia.com/v2/resources/nvidia/ngc-apps/ngc_cli/versions/${NGC_CLI_VERSION}/files/ngccli_linux.zip"
    findings = scan(
        "{\n"
        '  "onCreateCommand": {\n'
        f'    "tflint": "curl -fsSL \\"{tflint_url}\\" -o /tmp/tflint.zip && sudo unzip -o /tmp/tflint.zip -d /usr/local/bin",\n'
        f'    "ngc-cli": "curl -fsSL \\"{ngc_url}\\" -o /tmp/ngccli.zip && sudo unzip -o /tmp/ngccli.zip -d /usr/local"\n'
        "  }\n"
        "}\n",
        file_type="devcontainer",
        suffix=".json",
        name=".devcontainer/devcontainer.json",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id in {"curl-download", "curl-download-url-first", "github-release-download"}
    }
    assert tflint_url in deps
    assert ngc_url in deps
    assert not any(dep.endswith("\\") for dep in deps)


def test_curl_download_not_suppressed_by_later_unzip_dash_d():
    url = "https://api.ngc.nvidia.com/v2/resources/nvidia/ngc-apps/ngc_cli/versions/${NGC_CLI_VERSION}/files/ngccli_linux.zip"
    findings = scan(
        f'curl -fsSL "{url}" -o /tmp/ngccli.zip && sudo unzip -o /tmp/ngccli.zip -d /usr/local\n'
    )

    assert any(
        f.pattern_id == "curl-download-url-first"
        and f.extracted_dep == url
        for f in findings
    )


def test_devcontainer_lifecycle_command_ignores_jsonc_commented_downloads():
    findings = scan(
        "{\n"
        '  "onCreateCommand": {\n'
        '    // "old": "curl -fsSL https://github.com/example/tool/releases/download/v1/tool.zip -o /tmp/tool.zip",\n'
        '    "active": "echo ready"\n'
        "  }\n"
        "}\n",
        file_type="devcontainer",
        suffix=".json",
        name=".devcontainer/devcontainer.json",
    )

    assert not any(
        f.extracted_dep == "https://github.com/example/tool/releases/download/v1/tool.zip"
        for f in findings
    )


def test_javascript_node_https_detects_binary_download_from_url_constant():
    content = (
        "import { writeFileSync, chmodSync } from 'node:fs';\n"
        "import { get } from 'node:https';\n"
        "\n"
        "const VERSION = process.env.OPA_VERSION ?? '0.70.0';\n"
        "\n"
        "function fetch(url) {\n"
        "  return new Promise((resolve) => {\n"
        "    get(url, (res) => {\n"
        "      const chunks = [];\n"
        "      res.on('end', () => resolve(Buffer.concat(chunks)));\n"
        "    });\n"
        "  });\n"
        "}\n"
        "\n"
        "async function vendorOne() {\n"
        "  const target = { asset: 'opa_linux_amd64_static' };\n"
        "  const url = `https://openpolicyagent.org/downloads/v${VERSION}/${target.asset}`;\n"
        "  const buf = await fetchWithRetry(url);\n"
        "  writeFileSync('opa', buf);\n"
        "  chmodSync('opa', 0o755);\n"
        "}\n"
    )
    findings = scan(
        content,
        file_type="source_code",
        suffix=".mjs",
        name="policy-engine/sdk/node/scripts/fetch-opa.mjs",
    )
    expected_line = content.splitlines().index("  const buf = await fetchWithRetry(url);") + 1

    assert any(
        f.pattern_id == "node-http-binary-download"
        and f.extracted_dep == "https://openpolicyagent.org/downloads/v${VERSION}/${target.asset}"
        and f.line_number == expected_line
        for f in findings
    )


def test_javascript_node_https_expands_object_map_asset_template_downloads():
    content = (
        "import { writeFileSync, chmodSync } from 'node:fs';\n"
        "import { get } from 'node:https';\n"
        "\n"
        "const VERSION = process.env.OPA_VERSION ?? '0.70.0';\n"
        "const TARGETS = {\n"
        "  'linux-x64': { asset: 'opa_linux_amd64_static', bin: 'opa' },\n"
        "  'win32-x64': { asset: 'opa_windows_amd64.exe', bin: 'opa.exe' },\n"
        "};\n"
        "\n"
        "function fetch(url) {\n"
        "  return new Promise((resolve) => {\n"
        "    get(url, (res) => {\n"
        "      const chunks = [];\n"
        "      res.on('end', () => resolve(Buffer.concat(chunks)));\n"
        "    });\n"
        "  });\n"
        "}\n"
        "\n"
        "async function vendorOne(key) {\n"
        "  const target = TARGETS[key];\n"
        "  const url = `https://openpolicyagent.org/downloads/v${VERSION}/${target.asset}`;\n"
        "  const buf = await fetchWithRetry(url);\n"
        "  writeFileSync(target.bin, buf);\n"
        "  chmodSync(target.bin, 0o755);\n"
        "}\n"
    )
    findings = scan(
        content,
        file_type="source_code",
        suffix=".mjs",
        name="policy-engine/sdk/node/scripts/fetch-opa.mjs",
    )
    expected_line = content.splitlines().index("  const buf = await fetchWithRetry(url);") + 1

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "node-http-binary-download"
        and f.line_number == expected_line
    }
    assert deps == {
        "https://openpolicyagent.org/downloads/v${VERSION}/opa_linux_amd64_static",
        "https://openpolicyagent.org/downloads/v${VERSION}/opa_windows_amd64.exe",
    }


def test_javascript_node_https_detects_direct_literal_binary_download():
    findings = scan(
        "import https from 'node:https';\n"
        "import { createWriteStream } from 'node:fs';\n"
        "https.get('https://github.com/acme/tool/releases/download/v1/tool-linux-x64.tar.gz', (res) => {\n"
        "  res.pipe(createWriteStream('tool-linux-x64.tar.gz'));\n"
        "});\n",
        file_type="source_code",
        suffix=".mjs",
        name="scripts/download-tool.mjs",
    )

    assert any(
        f.pattern_id == "node-http-binary-download"
        and f.extracted_dep == "https://github.com/acme/tool/releases/download/v1/tool-linux-x64.tar.gz"
        and f.line_number == 3
        for f in findings
    )


def test_javascript_node_https_ignores_metadata_fetch_to_file():
    findings = scan(
        "import { writeFileSync } from 'node:fs';\n"
        "import { get } from 'node:https';\n"
        "async function refreshMetadata() {\n"
        "  const url = 'https://api.github.com/repos/acme/tool/releases';\n"
        "  const json = await fetchWithRetry(url);\n"
        "  writeFileSync('releases.json', JSON.stringify(json));\n"
        "}\n",
        file_type="source_code",
        suffix=".mjs",
        name="scripts/refresh-releases.mjs",
    )

    assert not any(f.pattern_id == "node-http-binary-download" for f in findings)


def test_javascript_http_client_detects_got_buffer_archive_download():
    findings = scan(
        "const got = await getGotInstance();\n"
        "const opts = {};\n"
        "const res = await got('https://github.com/microsoft/vscode-loc/archive/main.zip', opts).buffer();\n"
        "const content = await jszip.loadAsync(res);\n",
        file_type="source_code",
        suffix=".js",
        name="gulpfile.js",
    )

    assert any(
        f.pattern_id == "node-http-binary-download"
        and f.extracted_dep == "https://github.com/microsoft/vscode-loc/archive/main.zip"
        and f.line_number == 3
        for f in findings
    )


def test_javascript_http_client_detects_got_buffer_archive_url_constant():
    findings = scan(
        "const archiveUrl = 'https://github.com/acme/tool/archive/main.zip';\n"
        "const res = await got(archiveUrl).buffer();\n",
        file_type="source_code",
        suffix=".js",
        name="scripts/download-l10n.js",
    )

    assert any(
        f.pattern_id == "node-http-binary-download"
        and f.extracted_dep == "https://github.com/acme/tool/archive/main.zip"
        and f.line_number == 2
        for f in findings
    )


def test_javascript_http_client_ignores_json_api_arraybuffer_response():
    findings = scan(
        "const res = await axios.get('https://api.github.com/repos/acme/tool/releases', "
        "{ responseType: 'arraybuffer' });\n",
        file_type="source_code",
        suffix=".js",
        name="scripts/query-releases.js",
    )

    assert not any(f.pattern_id == "node-http-binary-download" for f in findings)


def test_javascript_download_helper_detects_urlish_source_to_nupkg_destination():
    findings = scan(
        "const https = require('node:https');\n"
        "async function downloadFile(url, dest) {\n"
        "  await downloadWithRetryAndRedirects(url, fs.createWriteStream(dest));\n"
        "}\n"
        "const downloadUrl = `${baseAddress}${nameLower}/${verLower}/${nameLower}.${verLower}.nupkg`;\n"
        "const nupkgPath = path.join(tempDir, `${artifact.name}.${artifact.version}.nupkg`);\n"
        "await downloadFile(downloadUrl, nupkgPath);\n",
        file_type="source_code",
        suffix=".cjs",
        name="sdk_v2/js/script/install-native.cjs",
    )

    assert any(
        f.pattern_id == "node-http-dynamic-download"
        and f.extracted_dep == "${downloadUrl}"
        for f in findings
    )


def test_javascript_download_helper_detects_urlish_source_to_zip_destination():
    findings = scan(
        "import * as https from 'https';\n"
        "import * as fs from 'fs';\n"
        "function downloadFileFromUrl(url: string, destinationPath: string): Promise<void> {\n"
        "  return new Promise((resolve) => https.get(url, response => {\n"
        "    const filePath = fs.createWriteStream(destinationPath);\n"
        "    response.pipe(filePath);\n"
        "    filePath.on('finish', () => resolve(undefined));\n"
        "  }));\n"
        "}\n"
        "const downloadUrl = getDownloadUrl(currentPlatform);\n"
        "const zipFilePath = `${installPath}.zip`;\n"
        "await downloadFileFromUrl(downloadUrl, zipFilePath);\n",
        file_type="source_code",
        suffix=".ts",
        name="vscode/packages/npm-package/install.ts",
    )

    assert any(
        f.pattern_id == "node-http-dynamic-download"
        and f.extracted_dep == "${downloadUrl}"
        for f in findings
    )


def test_javascript_download_helper_ignores_urlish_source_to_metadata_destination():
    findings = scan(
        "const https = require('node:https');\n"
        "async function downloadFile(url, dest) {\n"
        "  await downloadWithRetryAndRedirects(url, fs.createWriteStream(dest));\n"
        "}\n"
        "await downloadFile(downloadUrl, manifestPath);\n",
        file_type="source_code",
        suffix=".cjs",
        name="scripts/download-manifest.cjs",
    )

    assert not any(f.pattern_id == "node-http-dynamic-download" for f in findings)


def test_dockerfile_add_detects_remote_binary_artifacts():
    findings = scan(
        "ADD https://www.python.org/ftp/python/3.9.7/python-3.9.7-amd64.exe python-installer.exe\n"
        "ADD https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.18+8/OpenJDK17U-jdk_x64_linux_hotspot_17.0.18_8.tar.gz /jdk.tar.gz\n"
        'ADD ["https://dl.google.com/android/repository/platform-tools_r36.0.2-linux.zip", "/platform-tools.zip"]\n',
        file_type="dockerfile",
        suffix=".Dockerfile",
        name="Dockerfile",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "dockerfile-add-remote-binary"
    }
    assert deps == {
        "https://www.python.org/ftp/python/3.9.7/python-3.9.7-amd64.exe",
        "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.18+8/OpenJDK17U-jdk_x64_linux_hotspot_17.0.18_8.tar.gz",
        "https://dl.google.com/android/repository/platform-tools_r36.0.2-linux.zip",
    }


def test_dockerfile_add_detects_extensionless_github_release_binary():
    findings = scan(
        "ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini\n",
        file_type="dockerfile",
        suffix=".Dockerfile",
        name="server/historian/Dockerfile",
    )

    assert any(
        f.pattern_id == "dockerfile-add-remote-binary"
        and f.extracted_dep == "https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini"
        for f in findings
    )


def test_dockerfile_add_ignores_non_binary_setup_script_and_prose():
    docker_findings = scan(
        "ADD https://deb.nodesource.com/setup_24.x /nodesource_setup.sh\n",
        file_type="dockerfile",
        suffix=".Dockerfile",
        name="Dockerfile",
    )
    prose_findings = scan(
        "Add https://learn.microsoft.com/en-us/microsoft-365-copilot/ as a knowledge source.\n",
        file_type="agent_instruction",
        suffix=".md",
        name="README.md",
    )

    assert not any(f.pattern_id == "dockerfile-add-remote-binary" for f in docker_findings)
    assert not any(f.pattern_id == "dockerfile-add-remote-binary" for f in prose_findings)


def test_archive_pipe_detects_curl_tar_download():
    findings = scan(
        "run: curl https://downloads.apache.org/ant/ivy/2.5.2/apache-ivy-2.5.2-bin.tar.gz "
        "| tar xOz apache-ivy-2.5.2/ivy-2.5.2.jar > /usr/share/ant/lib/ivy.jar\n",
        file_type="ci",
        suffix=".yml",
    )

    assert any(
        f.pattern_id == "archive-pipe-download"
        and f.extracted_dep == "https://downloads.apache.org/ant/ivy/2.5.2/apache-ivy-2.5.2-bin.tar.gz"
        for f in findings
    )


def test_archive_pipe_detects_curl_tar_download_with_options():
    findings = scan(
        "curl -Ls https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1682.tar.gz "
        "| tar xz -C ibmtpm\n",
        file_type="script",
    )

    assert any(
        f.pattern_id == "archive-pipe-download"
        and f.extracted_dep == "https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1682.tar.gz"
        for f in findings
    )


def test_archive_pipe_detects_dockerfile_backslash_continuation():
    findings = scan(
        "RUN cd /opt && \\\n"
        "    curl http://apache.claz.org/spark/spark-${APACHE_SPARK_VERSION}/spark-${APACHE_SPARK_VERSION}-bin-without-hadoop.tgz | \\\n"
        "        tar -xz && \\\n"
        "    ln -s spark-${APACHE_SPARK_VERSION}-bin-without-hadoop spark\n",
        file_type="dockerfile",
        suffix="Dockerfile",
        name="Dockerfile",
    )

    assert any(
        f.pattern_id == "archive-pipe-download"
        and f.extracted_dep == "http://apache.claz.org/spark/spark-${APACHE_SPARK_VERSION}/spark-${APACHE_SPARK_VERSION}-bin-without-hadoop.tgz"
        for f in findings
    )


def test_archive_pipe_ignores_checksum_continuation():
    findings = scan(
        "curl https://example.com/tool.tar.gz | \\\n"
        "  sha256sum --check\n",
        file_type="script",
    )

    assert not any(f.pattern_id == "archive-pipe-download" for f in findings)


def test_archive_pipe_avoids_duplicate_when_wget_direct_download_exists():
    findings = scan(
        "wget https://downloads.apache.org/hadoop/common/hadoop-3.2.1/hadoop-3.2.1.tar.gz -O - | \\\n"
        "  tar -xz\n",
        file_type="script",
    )

    assert any(
        f.pattern_id == "wget-download"
        and f.extracted_dep == "https://downloads.apache.org/hadoop/common/hadoop-3.2.1/hadoop-3.2.1.tar.gz"
        for f in findings
    )
    assert not any(
        f.pattern_id == "archive-pipe-download"
        and f.extracted_dep == "https://downloads.apache.org/hadoop/common/hadoop-3.2.1/hadoop-3.2.1.tar.gz"
        for f in findings
    )


def test_archive_pipe_ignores_non_artifact_url():
    findings = scan(
        "curl -Ls https://get.nexte.st/latest/linux | tar zxf - -C \"$HOME/.cargo/bin\"\n",
        file_type="ci",
        suffix=".yml",
    )

    assert not any(f.pattern_id == "archive-pipe-download" for f in findings)


def test_detects_playwright_browser_install_via_npx_and_python():
    findings = scan(
        "run: npx playwright install chromium --with-deps\n"
        "python -m playwright install --with-deps firefox\n",
        file_type="ci",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "playwright-browser-install"
    }
    assert deps == {"chromium", "firefox"}


def test_detects_playwright_core_browser_install_via_npm_exec():
    findings = scan(
        "RUN npm exec --no -- playwright-core install chromium && "
        "npm exec --no -- playwright-core install webkit\n",
        file_type="dockerfile",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "playwright-browser-install"
    }
    assert deps == {"chromium", "webkit"}


def test_detects_playwright_default_browser_install_in_package_json_script():
    scanner = BinaryDownloadScanner(Config())
    content = '{ "scripts": { "pretest": "playwright install --with-deps" } }\n'
    target = FileTarget(path=Path("package.json"), rel_path="package.json", file_type="package_config")
    findings = scanner.scan_file_content(target, content, content.splitlines())

    assert any(
        f.pattern_id == "playwright-browser-install"
        and f.extracted_dep == "playwright-browsers"
        for f in findings
    )


def test_playwright_browser_install_ignores_install_deps_and_guidance():
    findings = scan(
        "npx playwright install-deps\n"
        'echo "npx playwright install chromium"\n'
        "# npx playwright install firefox\n"
        "npx playwright install webkit\n",
        file_type="script",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "playwright-browser-install"
    ]
    assert deps == ["webkit"]


def test_playwright_browser_install_ignores_non_control_markdown_example():
    findings = scan(
        "# Setup\n\nRun `npx playwright install chromium` before local browser tests.\n",
        file_type="agent_instruction",
        suffix=".md",
        name="README.md",
    )

    assert not any(f.pattern_id == "playwright-browser-install" for f in findings)


def test_playwright_browser_install_ignores_prose_and_dynamic_browser_input():
    findings = scan(
        "If there is no Playwright install, bootstrap one later.\n"
        "npx playwright install --with-deps ${{ inputs.browsers-to-install }}\n"
        "npx playwright install --with-deps chromium\n",
        file_type="github_action",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "playwright-browser-install"
    ]
    assert deps == ["chromium"]


def test_detects_puppeteer_browser_install_via_npx_and_package_script():
    findings = scan(
        "run: npx puppeteer browsers install chrome\n"
        '"test:jest": "assign-test-ports && '
        'pnpm puppeteer browsers install chrome-headless-shell && pnpm -r test:jest"\n',
        file_type="ci",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "puppeteer-browser-install"
    }
    assert deps == {"chrome", "chrome-headless-shell"}


def test_detects_puppeteer_browser_install_via_exec_and_package_cli():
    findings = scan(
        "RUN npm exec --no -- @puppeteer/browsers install firefox && "
        "yarn exec puppeteer browsers install chromedriver\n",
        file_type="dockerfile",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "puppeteer-browser-install"
    }
    assert deps == {"firefox", "chromedriver"}


def test_puppeteer_browser_install_ignores_install_deps_guidance_and_dynamic_input():
    findings = scan(
        "npx puppeteer browsers install-deps\n"
        'echo "npx puppeteer browsers install chrome"\n'
        "# npx puppeteer browsers install firefox\n"
        "npx puppeteer browsers install ${{ inputs.browser }}\n"
        "npx puppeteer browsers install chromium\n",
        file_type="script",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "puppeteer-browser-install"
    ]
    assert deps == ["chromium"]


def test_puppeteer_browser_install_ignores_non_control_markdown_example():
    findings = scan(
        "# Setup\n\n"
        "Run `npx puppeteer browsers install chrome` before local browser tests.\n"
        "You can also run `@puppeteer/browsers install chrome` directly.\n",
        file_type="agent_instruction",
        suffix=".md",
        name="README.md",
    )

    assert not any(f.pattern_id == "puppeteer-browser-install" for f in findings)


def test_ignores_powershell_webclient_checksum_text_download():
    findings = scan(
        '$client.DownloadFile("http://windows.php.net/downloads/releases/sha256sum.txt", '
        '"c:\\projects\\sha256sum.txt");\n',
        suffix=".ps1",
    )

    assert not any(f.pattern_id == "powershell-webclient-download" for f in findings)


def test_ignores_powershell_invoke_webrequest_checksum_text_download():
    findings = scan(
        'Invoke-WebRequest -Uri "https://github.com/$Repo/releases/download/$tag/checksums.txt" '
        "-OutFile $checksumsPath -UseBasicParsing\n",
        suffix=".ps1",
    )

    assert not any(f.pattern_id == "powershell-invoke-webrequest" for f in findings)


def test_ignores_checksum_sidecar_downloads():
    findings = scan(
        'curl -LO "https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl.sha256"\n'
        'curl -LO "https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl"\n'
    )

    assert not any(
        f.pattern_id == "curl-download"
        and f.extracted_dep == "https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl.sha256"
        for f in findings
    )
    assert any(
        f.pattern_id == "curl-download"
        and f.extracted_dep == "https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl"
        for f in findings
    )


def test_ignores_github_release_checksum_sidecar_downloads():
    sidecar_url = "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-x86_64.sha256"
    binary_url = "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-x86_64"
    findings = scan(
        f'curl -sSfL "{binary_url}" \\\n'
        '  -o "${COMPOSE_TMP}/docker-compose"\n'
        f'curl -sSfL "{sidecar_url}" \\\n'
        '  -o "${COMPOSE_TMP}/docker-compose.sha256"\n'
    )

    assert any(
        f.pattern_id == "github-release-download"
        and f.extracted_dep == binary_url
        for f in findings
    )
    assert not any(
        f.pattern_id == "github-release-download"
        and f.extracted_dep == sidecar_url
        for f in findings
    )


def test_detects_bitsadmin_download_with_github_expressions():
    url = (
        "https://download.unity3d.com/download_unity/${{ needs.compute.outputs.UNITY_HASH }}/"
        "Windows64EditorInstaller/UnitySetup64-${{ needs.compute.outputs.UNITY_FULL_VERSION }}.exe"
    )
    findings = scan(
        f'cmd /c bitsadmin /TRANSFER unity /DOWNLOAD /PRIORITY foreground "{url}" "%CD%\\unitysetup.exe"\n',
        "ci",
        ".yml",
    )

    assert any(
        f.pattern_id == "bitsadmin-download"
        and f.extracted_dep == url
        for f in findings
    )


def test_ignores_binary_download_in_non_control_markdown_fence():
    findings = scan(
        "Download the sample data:\n\n"
        "```bash\n"
        "curl -o sample.bin https://example.com/downloads/sample.bin\n"
        "```\n",
        file_type="agent_instruction",
        name="readme.md",
    )

    assert not any(f.pattern_id == "curl-download" for f in findings)


def test_ignores_binary_download_in_non_control_markdown_inline_code():
    findings = scan(
        "On Windows, run `iwr https://example.com/downloads/tool.zip -OutFile tool.zip`.\n",
        file_type="agent_instruction",
        name="README.md",
    )

    assert not any(f.pattern_id == "powershell-invoke-webrequest" for f in findings)


def test_ignores_binary_download_in_blog_markdown_fence():
    findings = scan(
        "To install nvm, run:\n\n"
        "```sh\n"
        "wget -qO- https://raw.githubusercontent.com/nvm-sh/nvm/v0.37.2/install.sh | bash\n"
        "```\n",
        file_type="agent_instruction",
        name="blogs/2020/12/03/chromebook-get-started.md",
    )

    assert not any(f.pattern_id == "wget-download" for f in findings)


def test_ignores_binary_download_in_post_markdown_fence():
    findings = scan(
        "Download the helper script:\n\n"
        "```bash\n"
        "curl -O https://microsoft.github.io/blog/assets/GrantDelegatedPermissions.ps1\n"
        "chmod +x GrantDelegatedPermissions.ps1\n"
        "```\n",
        file_type="agent_instruction",
        name="_posts/2025-11-11-mcs-http-connector-sso.md",
    )

    assert not any(f.pattern_id in {"curl-download", "chmod-downloaded-binary"} for f in findings)


def test_ignores_binary_download_in_install_guide_markdown_fence():
    findings = scan(
        "### Step 1. Install PHP\n"
        "```bash\n"
        "wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg\n"
        "```\n",
        file_type="agent_instruction",
        name="Linux-mac-install.md",
    )

    assert not any(f.pattern_id == "wget-download" for f in findings)


def test_ignores_binary_download_in_docs_markdown_fence():
    findings = scan(
        "Download the sample archive:\n\n"
        "```bash\n"
        "curl -LO https://example.com/downloads/sample.zip\n"
        "```\n",
        file_type="agent_instruction",
        name="docs/get-started/download-sample.md",
    )

    assert not any(f.pattern_id == "curl-download" for f in findings)


def test_detects_binary_download_in_prompt_markdown_fence():
    findings = scan(
        "Download the quick install script:\n\n"
        "```bash\n"
        "curl -fsSL https://raw.githubusercontent.com/microsoft/lisa/main/installers/quick-install.sh -o quick-install.sh\n"
        "chmod +x quick-install.sh\n"
        "```\n",
        file_type="agent_instruction",
        name=".github/prompts/install-lisa.prompt.md",
    )

    assert any(
        f.pattern_id == "curl-download-url-first"
        and f.extracted_dep == "https://raw.githubusercontent.com/microsoft/lisa/main/installers/quick-install.sh"
        for f in findings
    )


def test_detects_binary_download_in_skill_markdown_fence():
    findings = scan(
        "Fetch the required tool:\n\n"
        "```bash\n"
        "curl -o tool.bin https://example.com/downloads/tool.bin\n"
        "```\n",
        file_type="agent_instruction",
        name="SKILL.md",
    )

    assert any(
        f.pattern_id == "curl-download"
        and f.extracted_dep == "https://example.com/downloads/tool.bin"
        for f in findings
    )


def test_cloud_storage_download_reports_source_uri_and_trims_markdown_code_span_suffix():
    findings = scan(
        "| `aws s3 cp s3://prod-bot-artifacts/deploys/function.zip function.zip` | Download file |\n",
        file_type="agent_instruction",
    )

    assert any(
        f.pattern_id == "cloud-storage-download"
        and f.extracted_dep == "s3://prod-bot-artifacts/deploys/function.zip"
        for f in findings
    )
    assert not any(
        f.pattern_id == "cloud-storage-download"
        and f.extracted_dep.endswith("`")
        for f in findings
    )


def test_cloud_storage_download_ignores_placeholder_artifact_bucket():
    findings = scan(
        "| `aws s3 cp s3://my-bot-artifacts/deploys/function.zip ./function.zip` | Download file |\n",
        file_type="agent_instruction",
    )

    assert not any(f.pattern_id == "cloud-storage-download" for f in findings)


def test_cloud_storage_download_ignores_upload_destination_uri():
    findings = scan(
        "| `aws s3 cp function.zip s3://my-bot-artifacts/deploys/function.zip` | Upload file |\n",
        file_type="agent_instruction",
    )

    assert not any(f.pattern_id == "cloud-storage-download" for f in findings)


def test_cloud_storage_download_reports_gsutil_source_uri_with_flags():
    findings = scan(
        "gsutil cp -r gs://my-bucket/toolchain ./toolchain\n",
        file_type="ci",
    )

    assert any(
        f.pattern_id == "cloud-storage-download"
        and f.extracted_dep == "gs://my-bucket/toolchain"
        for f in findings
    )


def test_detects_curl_variable_download_before_output_flag():
    findings = scan('curl "$uri" -sSL --retry 5 --create-dirs -o "$path" --fail\n')

    assert any(
        f.pattern_id == "curl-var-download" and f.extracted_dep == "$uri"
        for f in findings
    )
    assert not any(f.extracted_dep == "$path" for f in findings)


def test_detects_curl_download_to_binary_from_lowercase_weburl_variable():
    findings = scan(
        'curl -f -s --connect-timeout 30 --retry 5 --retry-delay 60 '
        '--compressed -L -o "CitrixWorkspace.dmg" "$weburl"\n'
    )

    assert any(
        f.pattern_id == "curl-var-download" and f.extracted_dep == "$weburl"
        for f in findings
    )


def test_curl_variable_download_still_ignores_curl_options_variable():
    findings = scan('curl $curl_options -o "$out_path" "$weburl"\n')

    assert any(
        f.pattern_id == "curl-var-download" and f.extracted_dep == "$weburl"
        for f in findings
    )
    assert not any(f.extracted_dep == "$curl_options" for f in findings)


def test_dedupes_repeated_same_file_variable_downloads():
    findings = scan(
        'curl --output "a.py" ${baseUrl}${pythonScriptPath}"a.py"\n'
        'curl --output "b.py" ${baseUrl}${pythonScriptPath}"b.py"\n'
        'curl --output "$requirementFile" "$requirementFileUrl"\n'
    )

    deps = [
        f.extracted_dep for f in findings
        if f.pattern_id == "curl-var-download"
    ]
    assert deps == ["${baseUrl}${pythonScriptPath}", "$requirementFileUrl"]


def test_detects_curl_remote_name_variable_url():
    findings = scan('curl -SLO "$BaseUrl"/"$package".tgz\n')

    assert any(
        f.pattern_id == "curl-var-download" and f.extracted_dep.startswith("$BaseUrl")
        for f in findings
    )
    assert not any(f.extracted_dep == "$package" for f in findings)


def test_detects_curl_remote_name_literal_url_without_output_dir_variable_noise():
    findings = scan(
        'curl -SLO --create-dirs --output-dir "$__RootfsDir"/usr/include/net '
        'https://raw.githubusercontent.com/illumos/illumos-gate/master/usr/src/uts/common/io/bpf/net/bpf.h\n'
    )

    assert any(
        f.pattern_id == "curl-download"
        and f.extracted_dep == "https://raw.githubusercontent.com/illumos/illumos-gate/master/usr/src/uts/common/io/bpf/net/bpf.h"
        for f in findings
    )
    assert not any(f.pattern_id == "curl-var-download" for f in findings)


def test_detects_chained_curl_remote_name_downloads_once_each():
    findings = scan(
        "RUN curl -O https://download.example.com/driver.apk "
        "&& curl -O https://download.example.com/tools.apk\n",
        file_type="dockerfile",
    )

    curl_findings = [f for f in findings if f.pattern_id == "curl-download"]
    assert [f.extracted_dep for f in curl_findings] == [
        "https://download.example.com/driver.apk",
        "https://download.example.com/tools.apk",
    ]
    assert not any(f.pattern_id == "curl-download-url-first" for f in findings)


def test_curl_download_keeps_github_expression_inside_url():
    url = (
        "https://github.com/mstorsjo/llvm-mingw/releases/download/20220906/"
        "${{ env.LLVM-MINGW-TOOLCHAIN-NAME }}.tar.xz"
    )
    findings = scan(
        f"curl -L -o ${{{{ env.LLVM-MINGW-TOOLCHAIN-NAME }}}}.tar.xz {url}\n",
        file_type="ci",
    )

    assert any(
        f.pattern_id == "curl-download"
        and f.extracted_dep == url
        for f in findings
    )
    assert any(
        f.pattern_id == "github-release-download"
        and f.extracted_dep == url
        for f in findings
    )


def test_github_release_download_trims_subshell_closing_paren():
    url = "https://github.com/deluan/zsh-in-docker/releases/download/v1.1.5/zsh-in-docker.sh"
    findings = scan(
        f'RUN sh -c "$(curl -fsSL {url})" -- -p git\n',
        file_type="dockerfile",
    )

    assert any(
        f.pattern_id == "github-release-download"
        and f.extracted_dep == url
        for f in findings
    )
    assert not any(
        f.pattern_id == "github-release-download"
        and f.extracted_dep.endswith(")")
        for f in findings
    )


def test_curl_download_keeps_shell_substitutions_inside_url():
    url = "https://github.com/conda-forge/miniforge/releases/latest/download/Mambaforge-$(uname)-$(uname -m).sh"
    findings = scan(f'RUN curl -L -O "{url}"\n', file_type="dockerfile")

    assert any(
        f.pattern_id == "curl-download"
        and f.extracted_dep == url
        for f in findings
    )


def test_curl_download_does_not_use_downstream_gpg_output_flag():
    findings = scan(
        "RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc "
        "| gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg "
        '&& echo "deb https://packages.microsoft.com/debian/12/prod bookworm main" '
        "> /etc/apt/sources.list.d/mssql-release.list\n",
        file_type="dockerfile",
    )

    assert not any(
        f.pattern_id.startswith("curl-download")
        and f.extracted_dep == "https://packages.microsoft.com/debian/12/prod"
        for f in findings
    )


def test_curl_download_does_not_treat_hyphenated_url_path_as_output_flag():
    findings = scan(
        "RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key "
        "| tee /etc/apt/keyrings/nodesource.gpg > /dev/null\n",
        file_type="dockerfile",
    )

    assert not any(f.pattern_id == "curl-download-url-first" for f in findings)


def test_ignores_package_signing_key_downloads_as_binary_artifacts():
    findings = scan(
        "wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc "
        "| gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null\n"
        "curl -fsSL -o /tmp/microsoft.asc https://packages.microsoft.com/keys/microsoft.asc\n"
        "wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub\n"
        "sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc\n"
        "wget -qO- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg\n"
        'curl -fsSL "${NEXUS_PROXY_URL}"/repository/docker-public-key/gpg '
        "| sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/docker-archive-keyring.gpg\n",
        file_type="dockerfile",
    )

    assert not any(
        f.pattern_id in {"curl-download", "curl-download-url-first", "curl-var-download", "wget-download"}
        for f in findings
    )


def test_package_signing_key_filter_keeps_apk_package_downloads():
    findings = scan(
        "wget -q https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.26-r0/glibc-2.26-r0.apk "
        "-O /tmp/glibc.apk\n",
        file_type="dockerfile",
    )

    assert any(
        f.pattern_id == "wget-download"
        and f.extracted_dep == "https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.26-r0/glibc-2.26-r0.apk"
        for f in findings
    )


def test_ignores_curl_variable_output_path_with_command_substitution_source():
    findings = scan(
        'curl -SLo "$__RootfsDir/tmp/download/hosttools.zip" '
        '"$("$__RootfsDir/tmp/script/fetch.sh" --hosttools)"\n'
    )

    assert not any(f.pattern_id == "curl-var-download" for f in findings)


def test_ignores_curl_http_status_check_to_dev_null():
    findings = scan(
        'HTTP_CODE=$(curl -L -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" '
        '2>/dev/null || echo "000")\n',
        file_type="ci",
    )

    assert not any(f.pattern_id == "curl-var-download" for f in findings)


def test_ignores_curl_status_check_to_dev_null_inside_backticks():
    findings = scan(
        'HTTPD=`curl -A "Web Check" -sLk --connect-timeout 3 -w "%{http_code}\\n" '
        '"https://cosmos:8081/_explorer/emulator.pem" -o /dev/null`\n'
    )

    assert not any(f.pattern_id.startswith("curl-download") for f in findings)


def test_chmod_downloaded_binary_ignores_prior_null_output_status_probe():
    findings = scan(
        'LATEST=$(basename "$(curl -fsSL -o /dev/null -w "%{url_effective}" '
        'https://github.com/docker/compose/releases/latest)")\n'
        'curl -fsSL "https://github.com/docker/compose/releases/download/${LATEST}/docker-compose-$(uname -s)-$(uname -m)" '
        "-o /usr/local/bin/docker-compose\n"
        "chmod +x /usr/local/bin/docker-compose\n"
    )

    chmod_findings = [f for f in findings if f.pattern_id == "chmod-downloaded-binary"]
    assert len(chmod_findings) == 1
    assert chmod_findings[0].extracted_dep.startswith(
        "https://github.com/docker/compose/releases/download/${LATEST}/docker-compose-"
    )
    assert not chmod_findings[0].extracted_dep.endswith("/latest)\")")


def test_chmod_downloaded_binary_drops_closing_quote_from_wget_url():
    findings = scan(
        'wget -qO /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64"\n'
        "chmod +x /usr/local/bin/yq\n"
    )

    assert any(
        f.pattern_id == "chmod-downloaded-binary"
        and f.extracted_dep == "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64"
        for f in findings
    )


def test_chmod_downloaded_binary_keeps_command_substitution_inside_url():
    url = "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    findings = scan(
        f'curl -LO "{url}"\n'
        "chmod +x ./kubectl\n"
    )

    assert any(
        f.pattern_id == "chmod-downloaded-binary"
        and f.extracted_dep == url
        for f in findings
    )


def test_chmod_downloaded_binary_ignores_prior_github_api_metadata_lookup():
    findings = scan(
        'latest_ghqr="$(curl -sL https://api.github.com/repos/microsoft/ghqr/releases/latest '
        '| jq -r ".tag_name")"\n'
        'wget https://github.com/microsoft/ghqr/releases/download/$latest_ghqr/ghqr-linux-amd64.zip '
        "-O ghqr.zip\n"
        "chmod +x ghqr\n"
    )

    chmod_findings = [f for f in findings if f.pattern_id == "chmod-downloaded-binary"]
    assert not any(
        f.extracted_dep.startswith("https://api.github.com/")
        for f in chmod_findings
    )


def test_detects_download_helper_url_argument():
    findings = scan(
        '& ${{github.workspace}}\\scripts\\Download-AndVerify.ps1 '
        '-Url "https://download.sysinternals.com/files/Procdump.zip" '
        '-DestinationPath $procDumpZipPath -ExpectedHash $env:PROCDUMP_EXPECTED_HASH\n',
        file_type="ci",
    )

    assert any(
        f.pattern_id == "download-helper-url"
        and f.extracted_dep == "https://download.sysinternals.com/files/Procdump.zip"
        for f in findings
    )


def test_wget_literal_url_with_variable_output_is_not_double_counted():
    findings = scan(
        'wget "http://www.antlr2.org/download/antlr-${version}.tar.gz" '
        '-O "${name}-${version}.orig.tar.gz"\n'
    )
    pattern_ids = [f.pattern_id for f in findings]
    assert "wget-download" in pattern_ids
    assert "wget-var-download" not in pattern_ids


def test_wget_quoted_url_drops_closing_quote():
    findings = scan('wget -q "https://example.com/releases/tool.tar.bz2"\n')

    assert any(
        f.pattern_id == "wget-download"
        and f.extracted_dep == "https://example.com/releases/tool.tar.bz2"
        for f in findings
    )


def test_ignores_reserved_example_downloads_in_test_fixture_path():
    findings = scan(
        "curl -o /tmp/tool.tar.gz https://example.com/tool.tar.gz\n"
        "wget https://example.com/other-tool.zip -O /tmp/other-tool.zip\n",
        name="scripts/tests/fixtures/Security/insecure-download.sh",
    )

    assert findings == []


def test_keeps_real_external_downloads_in_test_fixture_path():
    findings = scan(
        "curl -o /tmp/tool.tar.gz https://github.com/microsoft/winget-cli/releases/download/v1.0/tool.tar.gz\n",
        name="scripts/tests/fixtures/Security/insecure-download.sh",
    )

    assert any(
        f.pattern_id in {"curl-download", "github-release-download"}
        and f.extracted_dep == "https://github.com/microsoft/winget-cli/releases/download/v1.0/tool.tar.gz"
        for f in findings
    )


def test_curl_download_drops_trailing_shell_separator_from_url():
    url = "https://github.com/summerwind/h2spec/releases/download/$H2SPEC_VERSION/h2spec_linux_amd64.tar.gz"
    findings = scan(f"if ! curl -L --output h2spec_linux_amd64.tar.gz {url}; then\n")

    deps = {
        (f.pattern_id, f.extracted_dep)
        for f in findings
        if f.pattern_id in {"curl-download", "github-release-download"}
    }
    assert ("curl-download", url) in deps
    assert ("github-release-download", url) in deps
    assert not any(dep.endswith(";") for _, dep in deps)


def test_ignores_ellipsis_placeholder_download_url_in_skill_doc():
    findings = scan(
        "For review-first installs:\n\n"
        "```bash\n"
        "curl -fsSL https://.../install.sh -o install.sh\n"
        "```\n",
        file_type="agent_instruction",
        suffix=".md",
        name="SKILL.md",
    )

    assert findings == []


def test_ignores_angle_placeholder_download_url_in_skill_doc():
    findings = scan(
        'curl -sL -o onnx.tgz "https://github.com/onnx/onnx/archive/<commit-or-tag>.tar.gz"\n',
        file_type="agent_instruction",
        suffix=".md",
        name=".agents/skills/onnx-opset-bump-checklist/SKILL.md",
    )

    assert findings == []


def test_ignores_variable_download_assigned_angle_placeholder_url():
    findings = scan(
        'URL="https://github.com/onnx/onnx/archive/<commit-or-refs/tags/vX.Y.0>.zip"\n'
        'curl -sL -o onnx.zip "$URL" && sha1sum onnx.zip\n',
        file_type="agent_instruction",
        suffix=".md",
        name=".agents/skills/onnx-opset-bump-checklist/SKILL.md",
    )

    assert findings == []


def test_wget_download_keeps_shell_substitution_inside_url():
    url = "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb"
    findings = scan(f'wget -q "{url}" -O /tmp/ms.deb\n')

    assert any(
        f.pattern_id == "wget-download"
        and f.extracted_dep == url
        for f in findings
    )


def test_ignores_wget_probe_to_dev_null():
    findings = scan("wget -q -O /dev/null -T 2 http://$TARGET_IP:80/ 2>&1 || true\n")

    assert not any(f.pattern_id == "wget-download" for f in findings)


def test_ignores_wget_variable_spider_probe_to_dev_null():
    findings = scan(
        'file_size=$(wget --spider --server-response -O /dev/null "$zip_uri" '
        "2>&1 | grep -i 'Content-Length:')\n"
    )

    assert not any(f.pattern_id == "wget-var-download" for f in findings)


def test_ignores_wget_stdout_directory_index_scrape():
    findings = scan(
        "package=$(wget -qO- http://security.ubuntu.com/ubuntu/pool/main/o/openssl/ "
        "| grep -oP '(libssl1.1_1.1.1f.*?_amd64.deb)' | head -1)\n"
    )

    assert not any(f.pattern_id == "wget-download" for f in findings)


def test_ignores_wget_stdout_text_metadata_lookup_without_pipe():
    findings = scan("wget -qO- https://dl.k8s.io/release/stable.txt\n")

    assert not any(f.pattern_id == "wget-download" for f in findings)


def test_wget_stdout_script_pipe_is_still_reported():
    findings = scan("wget -qO- https://example.com/install.sh | bash\n")

    assert any(
        f.pattern_id == "wget-download"
        and f.extracted_dep == "https://example.com/install.sh"
        for f in findings
    )


def test_ignores_direct_text_metadata_downloads():
    findings = scan(
        "wget https://raw.githubusercontent.com/example/tool/main/dictionaries/base.txt\n"
        "curl -o version.txt https://example.com/latest_version.txt\n"
    )

    assert not any(f.pattern_id in {"curl-download", "wget-download"} for f in findings)


def test_text_metadata_filter_keeps_archives():
    findings = scan("wget https://example.com/downloads/tool.tar.gz -O tool.tar.gz\n")

    assert any(
        f.pattern_id == "wget-download"
        and f.extracted_dep == "https://example.com/downloads/tool.tar.gz"
        for f in findings
    )


def test_ignores_yum_repo_config_downloads():
    findings = scan(
        "wget -P /etc/yum.repos.d/ https://packages.efficios.com/repo.files/EfficiOS-RHEL7-x86-64.repo\n"
        "curl -s https://packages.microsoft.com/config/rhel/7/prod.repo > /etc/yum.repos.d/mssql-release.repo\n"
    )

    assert not any(
        f.pattern_id in {"curl-download", "wget-download"}
        and f.extracted_dep in {
            "https://packages.efficios.com/repo.files/EfficiOS-RHEL7-x86-64.repo",
            "https://packages.microsoft.com/config/rhel/7/prod.repo",
        }
        for f in findings
    )


def test_ignores_static_web_asset_downloads():
    findings = scan(
        "sudo wget -q https://raw.githubusercontent.com/example/site/main/index.html -O /var/www/html/index.html\n"
        "sudo wget -q https://raw.githubusercontent.com/example/site/main/logo.png -O /var/www/html/logo.png\n"
        "sudo wget -q https://raw.githubusercontent.com/example/site/main/stylesheet.css -O /var/www/html/stylesheet.css\n"
    )

    assert not any(f.pattern_id == "wget-download" for f in findings)


def test_static_web_asset_filter_keeps_package_downloads():
    findings = scan(
        "wget -q https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb\n"
    )

    assert any(
        f.pattern_id == "wget-download"
        and f.extracted_dep == "https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb"
        for f in findings
    )


def test_ignores_downloaded_apt_repo_package_installed_with_dpkg():
    url = "https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb"
    findings = scan(
        f"wget {url} -O packages-microsoft-prod.deb\n"
        "sudo dpkg -i packages-microsoft-prod.deb\n"
    )

    assert not any(
        f.pattern_id == "wget-download"
        and f.extracted_dep == url
        for f in findings
    )


def test_ignores_downloaded_apt_repo_package_installed_with_dpkg_wrapper():
    url = "https://packages.microsoft.com/config/${DISTRO}/${VERSION}/packages-microsoft-prod.deb"
    findings = scan(
        f'curl -sSL -O "{url}"\n'
        "dpkg_install packages-microsoft-prod.deb\n"
    )

    assert not any(
        f.pattern_id == "curl-download"
        and f.extracted_dep == url
        for f in findings
    )


def test_ignores_dockerfile_add_apt_repo_package_installed_with_dpkg():
    url = "https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb"
    findings = scan(
        f"ADD {url} /packages-microsoft-prod.deb\n"
        "RUN apt-get update && apt-get install -y curl\n"
        "RUN dpkg -i packages-microsoft-prod.deb\n",
        file_type="dockerfile",
        suffix="Dockerfile",
        name="Dockerfile",
    )

    assert not any(
        f.pattern_id == "dockerfile-add-remote-binary"
        and f.extracted_dep == url
        for f in findings
    )


def test_ignores_wget_apt_repository_list_command_substitution():
    findings = scan(
        'sudo add-apt-repository "$(wget -qO- https://packages.microsoft.com/config/ubuntu/20.04/prod.list)"\n'
    )

    assert not any(f.pattern_id == "wget-download" for f in findings)


def test_ignores_curl_download_to_license_metadata_file():
    findings = scan(
        "curl -L https://raw.githubusercontent.com/qemu/qemu/$QEMU_VERSION/COPYING -o COPYING\n"
        "curl -L https://raw.githubusercontent.com/qemu/qemu/$QEMU_VERSION/LICENSE -o LICENSE\n",
        file_type="ci",
    )

    assert not any(f.pattern_id.startswith("curl-download") for f in findings)


def test_ignores_curl_download_to_openapi_yaml_metadata_file():
    findings = scan(
        "curl -o petstore.yaml "
        "https://raw.githubusercontent.com/OAI/OpenAPI-Specification/refs/heads/main/petstore.yaml\n",
        file_type="ci",
    )

    assert not any(f.pattern_id.startswith("curl-download") for f in findings)


def test_ignores_curl_remote_name_yaml_metadata_url():
    findings = scan(
        "curl -fsSLO https://raw.githubusercontent.com/googlemaps/openapi-specification/v1/openapi3.yml\n",
        file_type="ci",
    )

    assert not any(f.pattern_id.startswith("curl-download") for f in findings)


def test_detects_curl_assigned_download():
    findings = scan("SCRIPT=$(curl -fsSL https://get.example.com/configure.sh)\n")
    assert any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_current_ip_lookup():
    findings = scan("current_ip=$(curl -s https://ipinfo.io/ip)\n")
    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_json_metadata():
    findings = scan('SPRINT_JSON=$(curl -sf --max-time 5 "https://whatsprintis.it/?json") || exit 0\n')
    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_format_js_metadata_response():
    findings = scan(
        'bingapiresponse=$(curl -sL "https://www.bing.com/HPImageArchive.aspx?format=js&idx=0&n=1&mkt=en-US")\n'
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_version_text_metadata():
    findings = scan(
        'currentVersion=$(curl -LSs "https://armmf.adobe.com/arm-manifests/mac/AcrobatDC/acrobat/current_version.txt" '
        "| sed 's/\\.//g')\n"
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_html_version_scrape():
    findings = scan(
        'latestver=$(curl --user-agent "$UserAgent" -s -L '
        "https://www.citrix.com/downloads/workspace-app/mac/workspace-app-for-mac-latest.html#ctx-dl-eula-external "
        '| grep "<h1>Citrix " | awk \'{print $4}\')\n'
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_html_download_url_scrape():
    findings = scan(
        'url2=$(curl --user-agent "$UserAgent" -s -L '
        "https://www.citrix.com/downloads/workspace-app/mac/workspace-app-for-mac-latest.html#ctx-dl-eula-external "
        '| grep dmg | sed -n \'s/.*rel="//;s/".*//p\' | head -1)\n'
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_embedded_audience_url():
    findings = scan(
        'TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" '
        '"$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://hediet-screenshots.azurewebsites.net" '
        "| jq -r .value)\n",
        file_type="ci",
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_oidc_discovery_metadata():
    findings = scan(
        'HOME_TENANT_ID=$(curl -s "https://login.microsoftonline.com/${HOME_DOMAIN}/.well-known/openid-configuration" '
        '| python3 -c "import sys,json; print(json.load(sys.stdin)[\\"issuer\\"])")\n'
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_json_api_count_with_python_parser():
    findings = scan(
        'INSTANCE_COUNT=$(curl -s "https://$CATALOG_HOST/instances" 2>/dev/null '
        '| python3 -c "import json,sys; print(len(json.load(sys.stdin)))" '
        '2>/dev/null || echo "0")\n'
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_cloud_metadata_token():
    findings = scan(
        'ACCESS_TOKEN=$(curl -s -H "Metadata:true" '
        '"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01" '
        "| jq -r '.access_token')\n"
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_gcp_metadata_value():
    findings = scan(
        'PROJECT_ID=$(curl -H "Metadata-Flavor: Google" '
        '"http://metadata.google.internal/computeMetadata/v1/project/project-id")\n'
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_form_api_login_response():
    findings = scan(
        'login_response=$(curl "https://${OHDSI_WEB_API_URL}/WebAPI/user/login/db" '
        '--data-raw "login=$USER&password=$PASSWORD" --compressed -i)\n'
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_container_registry_tag_metadata():
    findings = scan(
        'tags_json=$(curl -s "https://${registry_host}/v2/${repo_path}/tags/list" 2>/dev/null || true)\n'
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_http_put_upload_response():
    findings = scan(
        'RESPONSE=$(curl -s -w "\\n%{http_code}" '
        '-X PUT "https://www.googleapis.com/upload/chromewebstore/v1.1/items/${EXTENSION_ID}" '
        '-H "Authorization: Bearer $TOKEN" -H "x-goog-api-version: 2" '
        '--upload-file package.zip)\n',
        file_type="ci",
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_variable_health_status_probe():
    findings = scan(
        'http_code=$(curl --insecure --silent --output "$api_response_file" '
        '--write-out %{http_code} "${TRE_URL}/api/health")\n'
    )

    assert not any(f.pattern_id == "curl-var-download" for f in findings)


def test_ignores_curl_json_api_post_response_capture():
    findings = scan(
        'HTTP_CODE=$(curl -sS -o "$WORK_DIR/marketplace_response.json" -w "%{http_code}" '
        '--max-time 60 --retry 2 -X POST '
        '"https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery" '
        '-H "Content-Type: application/json")\n'
    )

    assert not any(
        f.pattern_id in {"curl-download", "curl-download-url-first", "curl-assigned-download"}
        for f in findings
    )


def test_ignores_curl_api_post_response_capture_with_header_variable():
    findings = scan(
        'RESPONSE=$(curl -i -s -w "%{http_code}" -o /tmp/resp.out '
        '-X POST -H "Authorization: Bearer $GH_TOKEN" '
        '-H "Accept: application/vnd.github+json" '
        '-H "Content-Type: application/json" -d "$PAYLOAD" '
        '"https://api.github.com/repos/$REPO/issues/$PR_NUMBER/comments")\n',
        file_type="ci",
    )

    assert not any(
        f.pattern_id in {"curl-download", "curl-download-url-first", "curl-assigned-download", "curl-var-download"}
        for f in findings
    )


def test_ignores_curl_assigned_github_json_api_response():
    findings = scan(
        'reactions=$(curl -s -H "Accept: application/vnd.github.squirrel-girl-preview+json" '
        '-H "Authorization: token $GH_TOKEN" '
        'https://api.github.com/repos/$REPO/issues/$ISSUE/reactions)\n'
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_appcenter_json_api_response():
    findings = scan(
        'latestTestRunJson=$(curl -s -b -v -w "%{http_code}" '
        '-H "X-API-Token:$token" '
        '"https://api.appcenter.ms/v0.1/apps/$org/$app/test_runs/$latestTestRunId")\n'
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_ignores_curl_assigned_powerbi_json_api_response():
    findings = scan(
        'RAW=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" '
        'https://api.powerbi.com/v1.0/myorg/groups?%24top=5000 || true)\n'
    )

    assert not any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_keeps_curl_assigned_github_api_binary_accept_download():
    findings = scan(
        'asset=$(curl -sL -H "Accept: application/octet-stream" '
        'https://api.github.com/repos/example/tool/releases/assets/123)\n'
    )

    assert any(f.pattern_id == "curl-assigned-download" for f in findings)


def test_detects_nuget_package_url_variable_download():
    findings = scan(
        '$url = "https://www.nuget.org/api/v2/package/$pkg/$ver"\n'
        "curl -L -o $nupkg $url\n"
    )

    assert any(
        f.pattern_id == "nuget-package-download"
        and f.extracted_dep == "https://www.nuget.org/api/v2/package/$pkg/$ver"
        for f in findings
    )


def test_detects_powershell_dynamic_nuget_package_download_via_wrapper():
    findings = scan(
        '$nuGetVersionsResponse = Invoke-WebRequestWithProxyDetection -Uri $nuGetVersionsUrl -UseBasicParsing\n'
        '$nuGetDownloadUrl = ($nuGetVersionsResponse.Content | ConvertFrom-Json -ErrorAction Stop).packageContent\n'
        '$nuGetPackageFileName = $nuGetDownloadUrl.Split("/")[-1]\n'
        '$fullPathToDownloadedFile = "$($SaveTo)\\$($nuGetPackageFileName)"\n'
        'Invoke-WebRequestWithProxyDetection -Uri $nuGetDownloadUrl -OutFile $fullPathToDownloadedFile -UseBasicParsing\n',
        suffix=".ps1",
    )

    assert any(
        f.pattern_id == "powershell-dynamic-nuget-package-download"
        and f.extracted_dep == "$nugetdownloadurl"
        and f.line_number == 5
        for f in findings
    )


def test_ignores_powershell_dynamic_nuget_url_to_metadata_file():
    findings = scan(
        '$nuGetDownloadUrl = "https://api.nuget.org/v3/registration5-gz-semver2/package/index.json"\n'
        'Invoke-WebRequestWithProxyDetection -Uri $nuGetDownloadUrl -OutFile "registration.json" -UseBasicParsing\n',
        suffix=".ps1",
    )

    assert not any(
        f.pattern_id == "powershell-dynamic-nuget-package-download"
        for f in findings
    )


def test_resolves_variable_download_from_prior_url_assignment():
    findings = scan(
        'RUSTUP_URL="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"\n'
        'curl --proto "=https" --tlsv1.2 -sSf "${RUSTUP_URL}" -o "${RUSTUP_INIT}"\n'
        'curl --proto "=https" --tlsv1.2 -sSf "${RUSTUP_URL}.sha256" -o "${RUSTUP_HASH}"\n'
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "curl-var-download"
    }
    assert "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init" in deps
    assert "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init.sha256" not in deps
    assert "${RUSTUP_URL}" not in deps
    assert "${RUSTUP_URL}.sha256" not in deps


def test_resolves_batch_percent_variable_download_from_prior_set_assignment():
    findings = scan(
        'set PYTHON_VERSION=3.11.9\n'
        'set PYTHON_DOWNLOAD_URL="https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-embed-amd64.zip"\n'
        "curl --output python-archive.zip %PYTHON_DOWNLOAD_URL%\n",
        suffix=".cmd",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "curl-var-download"
    }
    assert "https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-embed-amd64.zip" in deps
    assert "%PYTHON_DOWNLOAD_URL%" not in deps


def test_resolved_variable_download_dedupes_against_nuget_url_finding():
    findings = scan(
        '$url = "https://www.nuget.org/api/v2/package/$pkg/$ver"\n'
        "curl -L -o $nupkg $url\n"
    )

    assert any(
        f.pattern_id == "nuget-package-download"
        and f.extracted_dep == "https://www.nuget.org/api/v2/package/$pkg/$ver"
        for f in findings
    )
    assert not any(
        f.pattern_id == "curl-var-download"
        and f.extracted_dep in {"$url", "https://www.nuget.org/api/v2/package/$pkg/$ver"}
        for f in findings
    )


def test_gh_release_download_skips_repo_and_dir_flags():
    findings = scan("gh release download -R microsoft/ccf \"$RELEASE_TAG\" -D release-assets\n")

    assert any(
        f.pattern_id == "gh-release-download"
        and f.extracted_dep == "$RELEASE_TAG"
        for f in findings
    )
    assert not any(
        f.pattern_id == "gh-release-download"
        and f.extracted_dep == "-R"
        for f in findings
    )


def test_gh_release_download_trims_quoted_tag_argument():
    findings = scan(
        'gh release download "${prev}" --repo "${GITHUB_REPOSITORY}" '
        "--pattern 'dep-sbom.spdx.json' --dir previous-sbom\n"
        'gh release download "v1.2.3" --repo example/tool\n'
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "gh-release-download"
    }
    assert "${prev}" in deps
    assert "v1.2.3" in deps
    assert '"${prev}"' not in deps
    assert '"v1.2.3"' not in deps


def test_chmod_downloaded_binary_does_not_cross_dockerfile_directives():
    findings = scan(
        "RUN curl https://sh.rustup.rs -sSf | sh -s -- -y\n"
        'ENV PATH="/root/.cargo/bin:${PATH}"\n'
        "RUN curl -sSL -o /tmp/sqlcmd.tar.bz2 "
        '"https://github.com/microsoft/go-sqlcmd/releases/download/v1.8.0/sqlcmd-linux-amd64.tar.bz2" \\\n'
        "    && tar -xjf /tmp/sqlcmd.tar.bz2 -C /usr/local/bin \\\n"
        "    && chmod +x /usr/local/bin/sqlcmd\n",
        file_type="dockerfile",
    )

    chmod_findings = [f for f in findings if f.pattern_id == "chmod-downloaded-binary"]
    deps = {f.extracted_dep.rstrip('"') for f in chmod_findings}
    assert "https://github.com/microsoft/go-sqlcmd/releases/download/v1.8.0/sqlcmd-linux-amd64.tar.bz2" in deps
    assert "https://sh.rustup.rs" not in deps
