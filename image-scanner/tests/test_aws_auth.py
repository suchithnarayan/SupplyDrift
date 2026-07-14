"""Tests for the AWS auth component (auth/aws.py)."""
from __future__ import annotations

import json

from image_scanner.auth.aws import AwsSession

STS = json.dumps(
    {"Credentials": {"AccessKeyId": "ASIA", "SecretAccessKey": "tmpsecret", "SessionToken": "tmptok"}}
)


def make_runner(handlers):
    calls = []

    def runner(cmd, env=None):
        calls.append((cmd, env))
        joined = " ".join(cmd)
        for needle, value in handlers.items():
            if needle in joined:
                return value
        return "{}"

    return runner, calls


def test_profile_uses_profile_flag_no_env():
    s = AwsSession.from_config({"profile": "prod", "region": "us-east-1"})
    assert s.cli_args() == ["aws", "--region", "us-east-1", "--profile", "prod"]
    assert s.env() == {}


def test_static_keys_export_env_no_profile():
    s = AwsSession.from_config(
        {"access_key_id": "AKIA", "secret_access_key": "SK", "session_token": "ST", "region": "r"}
    )
    assert s.env() == {
        "AWS_ACCESS_KEY_ID": "AKIA",
        "AWS_SECRET_ACCESS_KEY": "SK",
        "AWS_SESSION_TOKEN": "ST",
    }
    assert "--profile" not in s.cli_args()


def test_assume_role_resolves_temp_credentials():
    runner, calls = make_runner({"sts assume-role": STS})
    s = AwsSession.from_config(
        {"role_arn": "arn:aws:iam::123:role/Scanner", "profile": "base", "region": "us-east-1"},
        runner=runner,
    )
    env = s.env(now=1000)
    assert env["AWS_ACCESS_KEY_ID"] == "ASIA"
    assert env["AWS_SESSION_TOKEN"] == "tmptok"
    # The base identity (profile) is used for the assume-role call itself...
    assert any("--profile" in cmd and "assume-role" in cmd for cmd, _ in calls)
    # ...but downstream calls use the temp creds via env, not --profile.
    assert "--profile" not in s.cli_args()


def test_assume_role_is_cached():
    runner, calls = make_runner({"sts assume-role": STS})
    s = AwsSession.from_config({"role_arn": "arn:aws:iam::123:role/X", "region": "r"}, runner=runner)
    s.env(now=1000)
    s.env(now=1100)  # within TTL
    assert sum(1 for cmd, _ in calls if "assume-role" in cmd) == 1


def test_ecr_auth_mints_and_caches_token():
    runner, calls = make_runner({"get-login-password": "pull-token\n"})
    s = AwsSession.from_config({"region": "us-east-1"}, runner=runner)
    reg = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
    auth = s.ecr_auth(reg, now=1000)
    assert auth.username == "AWS" and auth.password == "pull-token" and auth.provider == "ecr"
    # Region inferred from the registry host; token cached on the second call.
    s.ecr_auth(reg, now=1100)
    assert sum(1 for cmd, _ in calls if "get-login-password" in cmd) == 1


def test_region_list_prefers_regions_then_region():
    assert AwsSession.from_config({"regions": ["a", "b"]}).region_list() == ["a", "b"]
    assert AwsSession.from_config({"region": "c"}).region_list() == ["c"]
    assert AwsSession.from_config({}).region_list() == []
