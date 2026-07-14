"""Tests for BuildExternalScanner package metadata handling."""
from __future__ import annotations

from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.build_external import BuildExternalScanner


def scan(content: str, file_type: str = "package_config", name: str = "package.json"):
    scanner = BuildExternalScanner(Config())
    target = FileTarget(path=Path(name), rel_path=name, file_type=file_type)
    return scanner.scan_file_content(target, content, content.splitlines())


def test_package_json_repository_url_is_not_npm_git_dependency():
    findings = scan(
        """{
  "repository": {
    "type": "git",
    "url": "git+https://github.com/microsoft/aspire.dev.git"
  }
}
"""
    )

    assert not any(f.pattern_id == "npm-git-dependency" for f in findings)


def test_package_json_repository_url_is_not_composer_vcs_repo():
    findings = scan(
        """{
  "repository": {
    "url": "https://github.com/microsoft/rushstack.git",
    "type": "git"
  }
}
"""
    )

    assert not any(f.pattern_id == "composer-vcs-repo" for f in findings)


def test_composer_json_vcs_repository_is_reported():
    findings = scan(
        """{
  "repositories": [
    {
      "url": "https://github.com/example/package.git",
      "type": "git"
    }
  ]
}
""",
        name="composer.json",
    )

    assert any(
        f.pattern_id == "composer-vcs-repo"
        and f.extracted_dep == "https://github.com/example/package.git"
        for f in findings
    )


def test_package_json_dependency_git_spec_is_reported():
    findings = scan(
        """{
  "dependencies": {
    "tool": "git+https://github.com/example/tool.git#main"
  }
}
"""
    )

    assert any(
        f.pattern_id == "npm-git-dependency"
        and f.extracted_dep == "git+https://github.com/example/tool.git#main"
        for f in findings
    )


def test_cargo_git_dependency_only_applies_to_cargo_toml():
    pyproject_findings = scan(
        'tool = { git = "https://github.com/example/tool.git", branch = "main" }\n',
        name="pyproject.toml",
    )
    cargo_findings = scan(
        'tool = { git = "https://github.com/example/tool.git", branch = "main" }\n',
        name="Cargo.toml",
    )

    assert not any(f.pattern_id == "cargo-git-dependency" for f in pyproject_findings)
    assert any(
        f.pattern_id == "cargo-git-dependency"
        and f.extracted_dep == "https://github.com/example/tool.git"
        for f in cargo_findings
    )


def test_cmake_fetchcontent_url_drops_closing_parenthesis():
    findings = scan(
        "FetchContent_Declare(macis GIT_REPOSITORY https://github.com/wavefunction91/MACIS)\n",
        file_type="build",
        name="CMakeLists.txt",
    )

    assert any(
        f.pattern_id == "cmake-fetchcontent"
        and f.extracted_dep == "https://github.com/wavefunction91/MACIS"
        for f in findings
    )


def test_cmake_external_project_url_drops_quote_and_closing_parenthesis():
    findings = scan(
        'ExternalProject_Add(foo URL "https://example.com/foo.tar.gz")\n',
        file_type="build",
        name="CMakeLists.txt",
    )

    assert any(
        f.pattern_id == "cmake-external-project"
        and f.extracted_dep == "https://example.com/foo.tar.gz"
        for f in findings
    )


def test_cmake_placeholder_external_deps_in_test_fixture_path_are_ignored():
    findings = scan(
        "FetchContent_Declare(\n"
        "  cmake_test\n"
        "  GIT_REPOSITORY https://github.com/example/test.git\n"
        ")\n"
        "FetchContent_Declare(\n"
        "  mylib\n"
        "  URL https://example.com/mylib-1.0.tar.gz\n"
        ")\n"
        "ExternalProject_Add(foobar\n"
        "  GIT_REPOSITORY git@github.com:FooCo/FooBar.git\n"
        ")\n",
        file_type="build",
        name="test/visual-syntax-test/CMakeLists.txt",
    )

    assert not any(f.pattern_id in {"cmake-fetchcontent", "cmake-external-project"} for f in findings)


def test_cmake_real_external_dep_in_test_fixture_path_is_reported():
    findings = scan(
        "FetchContent_Declare(\n"
        "  googletest\n"
        "  GIT_REPOSITORY https://github.com/google/googletest.git\n"
        ")\n",
        file_type="build",
        name="test/visual-syntax-test/CMakeLists.txt",
    )

    assert any(
        f.pattern_id == "cmake-fetchcontent"
        and f.extracted_dep == "https://github.com/google/googletest.git"
        for f in findings
    )


def test_makefile_download_trims_closing_quote():
    findings = scan(
        'download:\n\tcurl -o tool.zip "https://downloads.example.com/tool.zip"\n',
        file_type="build",
        name="Makefile",
    )

    assert any(
        f.pattern_id == "makefile-download"
        and f.extracted_dep == "https://downloads.example.com/tool.zip"
        for f in findings
    )


def test_makefile_json_api_call_is_not_artifact_download():
    findings = scan(
        'pin:\n\tcurl -H "Accept: application/json" "https://api.github.com/repos/example/tool/commits?sha=main" | jq -r .[0].sha > PIN\n',
        file_type="build",
        name="Makefile",
    )

    assert not any(f.pattern_id == "makefile-download" for f in findings)


def test_makefile_localhost_curl_is_not_external_artifact_download():
    findings = scan(
        "attest:\n"
        "\tcurl --unix-socket /var/run/azure-attestation-proxy/azure-attestation-proxy.sock "
        'http://localhost/attest -H "maa: ${MAA}"\n',
        file_type="build",
        name="Makefile",
    )

    assert not any(f.pattern_id == "makefile-download" for f in findings)


def test_maven_project_metadata_url_is_not_repository():
    findings = scan(
        "<project>\n"
        "  <url>http://maven.apache.org</url>\n"
        "</project>\n",
        file_type="build",
        name="pom.xml",
    )

    assert not any(f.pattern_id == "maven-non-standard-repo" for f in findings)


def test_maven_xmlns_url_is_not_url_variable_assignment():
    findings = scan(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"\n'
        '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
        "</project>\n",
        file_type="build",
        name="pom.xml",
    )

    assert not any(f.pattern_id == "url-variable-assignment" for f in findings)


def test_maven_repository_url_is_reported():
    findings = scan(
        "<project>\n"
        "  <repositories>\n"
        "    <repository>\n"
        "      <id>private</id>\n"
        "      <url>https://packages.example.com/maven</url>\n"
        "    </repository>\n"
        "  </repositories>\n"
        "</project>\n",
        file_type="build",
        name="pom.xml",
    )

    assert any(
        f.pattern_id == "maven-non-standard-repo"
        and f.extracted_dep == "https://packages.example.com/maven"
        for f in findings
    )


def test_gradle_pom_metadata_url_assignment_is_not_external_dependency_source():
    findings = scan(
        "publishing {\n"
        "  publications {\n"
        "    release(MavenPublication) {\n"
        "      pom {\n"
        "        url = 'https://github.com/microsoft/example'\n"
        "        licenses {\n"
        "          license {\n"
        "            url = 'https://github.com/microsoft/example/blob/main/LICENSE'\n"
        "          }\n"
        "        }\n"
        "        scm {\n"
        "          url = 'https://github.com/microsoft/example/tree/main'\n"
        "        }\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "repositories { maven { url 'https://jitpack.io' } }\n"
        "DOWNLOAD_URL = 'https://downloads.example.com/tool.zip'\n",
        file_type="build",
        name="build.gradle",
    )

    url_assignment_deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "url-variable-assignment"
    }
    assert url_assignment_deps == {"https://downloads.example.com/tool.zip"}
    assert any(
        f.pattern_id == "gradle-non-standard-repo"
        and f.extracted_dep == "https://jitpack.io"
        for f in findings
    )


def test_gradle_buildscript_standard_repositories_are_not_reported():
    findings = scan(
        "buildscript {\n"
        "  repositories {\n"
        '    maven { url "https://plugins.gradle.org/m2/" }\n'
        '    maven { url "https://maven.google.com" }\n'
        "  }\n"
        "}\n",
        file_type="build",
        name="build.gradle",
    )

    assert not any(f.pattern_id == "gradle-buildscript-repo" for f in findings)


def test_gradle_non_standard_repository_supports_uri_call():
    feed = "https://pkgs.dev.azure.com/MicrosoftDeviceSDK/DuoSDK-Public/_packaging/Duo-SDK-Feed/maven/v1"
    findings = scan(
        "repositories {\n"
        f'  maven {{ url = uri("{feed}") }}\n'
        "}\n",
        file_type="build",
        name="packages/app/android/app/build.gradle",
    )

    assert any(
        f.pattern_id == "gradle-non-standard-repo"
        and f.extracted_dep == feed
        for f in findings
    )


def test_gradle_non_standard_repository_supports_multiline_uri_call():
    feed = "https://pkgs.dev.azure.com/MicrosoftDeviceSDK/DuoSDK-Public/_packaging/Duo-SDK-Feed/maven/v1"
    findings = scan(
        "repositories {\n"
        "    maven {\n"
        f'        url = uri("{feed}")\n'
        "    }\n"
        "}\n",
        file_type="build",
        name="packages/app/android/app/build.gradle",
    )

    gradle_findings = [
        f for f in findings
        if f.pattern_id == "gradle-non-standard-repo"
    ]
    assert [f.extracted_dep for f in gradle_findings] == [feed]


def test_gradle_standard_repository_uri_call_is_not_reported():
    findings = scan(
        "repositories {\n"
        '  maven { url = uri("https://plugins.gradle.org/m2/") }\n'
        "}\n",
        file_type="build",
        name="android/build.gradle",
    )

    assert not any(f.pattern_id == "gradle-non-standard-repo" for f in findings)


def test_gradle_maven_local_repository_is_reported():
    findings = scan(
        "repositories {\n"
        "  mavenLocal()\n"
        "  mavenCentral()\n"
        "}\n",
        file_type="build",
        name="settings.gradle.kts",
    )

    assert any(
        f.pattern_id == "gradle-maven-local-repo"
        and f.extracted_dep == "mavenLocal()"
        for f in findings
    )


def test_gradle_flatdir_local_repository_is_reported():
    findings = scan(
        "allprojects {\n"
        "  repositories {\n"
        "    flatDir{dirs 'libs'}\n"
        "  }\n"
        "}\n",
        file_type="build",
        name="src/java/src/test/android/build.gradle",
    )

    assert any(
        f.pattern_id == "gradle-flatdir-repo"
        and f.extracted_dep == "dirs 'libs'"
        for f in findings
    )


def test_gradle_local_file_dependencies_are_reported():
    findings = scan(
        "dependencies {\n"
        "  classpath files('plugin-${version}.jar')\n"
        "  implementation fileTree(dir: 'libs', include: ['*.jar'])\n"
        "}\n",
        file_type="build",
        name="server/build.gradle",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "gradle-local-file-dependency"
    }
    assert deps == {
        "files('plugin-${version}.jar')",
        "fileTree(dir: 'libs', include: ['*.jar'])",
    }


def test_gradle_buildscript_custom_repository_is_reported():
    findings = scan(
        "buildscript {\n"
        "  repositories {\n"
        '    maven { url "https://packages.example.com/gradle" }\n'
        "  }\n"
        "}\n",
        file_type="build",
        name="build.gradle",
    )

    assert any(
        f.pattern_id == "gradle-buildscript-repo"
        and f.extracted_dep == "https://packages.example.com/gradle"
        for f in findings
    )


def test_maven_wrapper_distribution_url_is_maven_wrapper_url():
    findings = scan(
        "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.11/apache-maven-3.9.11-bin.zip\n"
        "wrapperUrl=https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.3.2/maven-wrapper-3.3.2.jar\n",
        file_type="build_wrapper",
        name="maven-wrapper.properties",
    )

    deps_by_pattern = {
        (f.pattern_id, f.extracted_dep)
        for f in findings
    }
    assert (
        "maven-wrapper-url",
        "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.11/apache-maven-3.9.11-bin.zip",
    ) in deps_by_pattern
    assert not any(f.pattern_id == "gradle-wrapper-url" for f in findings)


def test_gradle_wrapper_distribution_url_remains_gradle_wrapper_url():
    findings = scan(
        "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.14-bin.zip\n",
        file_type="build_wrapper",
        name="gradle-wrapper.properties",
    )

    assert any(
        f.pattern_id == "gradle-wrapper-url"
        and f.extracted_dep == "https://services.gradle.org/distributions/gradle-8.14-bin.zip"
        for f in findings
    )


def test_gradle_wrapper_under_test_fixtures_is_not_reported():
    findings = scan(
        "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.5-bin.zip\n",
        file_type="build_wrapper",
        name="extension/test-fixtures/gradle-groovy-default-build-file/gradle/wrapper/gradle-wrapper.properties",
    )

    assert not any(f.pattern_id == "gradle-wrapper-url" for f in findings)


def test_maven_wrapper_under_test_resources_is_not_reported():
    findings = scan(
        "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.6.3/apache-maven-3.6.3-bin.zip\n"
        "wrapperUrl=https://repo.maven.apache.org/maven2/io/takari/maven-wrapper/0.5.5/maven-wrapper-0.5.5.jar\n",
        file_type="build_wrapper",
        name="gradle-language-server/test-resources/spring-boot-webapp/.mvn/wrapper/maven-wrapper.properties",
    )

    assert not any(f.pattern_id == "maven-wrapper-url" for f in findings)


def test_terraform_local_module_source_is_not_provider_dependency():
    findings = scan(
        'module "resources" {\n'
        '  source = "../resources"\n'
        '}\n'
        'module "local" {\n'
        '  source = "./modules/local"\n'
        '}\n',
        file_type="iac",
        name="main.tf",
    )

    assert not any(f.pattern_id == "terraform-non-standard-provider" for f in findings)
    assert not any(f.pattern_id == "terraform-remote-module" for f in findings)


def test_terraform_non_standard_provider_source_is_reported():
    findings = scan(
        'terraform {\n'
        '  required_providers {\n'
        '    azapi = { source = "azure/azapi" }\n'
        '  }\n'
        '}\n',
        file_type="iac",
        name="versions.tf",
    )

    assert any(
        f.pattern_id == "terraform-non-standard-provider"
        and f.extracted_dep == "azure/azapi"
        for f in findings
    )
