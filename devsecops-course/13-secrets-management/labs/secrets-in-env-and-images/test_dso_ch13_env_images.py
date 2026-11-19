import copy
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

lf = load_lab_module(__file__, "leak_finder")
FIX = Path(__file__).parent / "fixtures"
CFG = lf.load_json(FIX / "image_config.json")
INSPECT = lf.load_json(FIX / "docker_inspect.json")
HISTORY = lf.load_json(FIX / "image_history.json")
COMPOSE = lf.load_yaml(FIX / "compose_before.yml")
LOG = (FIX / "app_startup.log").read_text()


def names(findings):
    return {f.name for f in findings}


def kinds(findings):
    return {f.kind for f in findings}


def test_image_config_env_leaks():
    found = lf.scan_image_config(CFG)
    assert {"DB_PASSWORD", "API_TOKEN", "DATABASE_URL"} <= names(found)
    assert "SIGNING_KEY_FILE" not in names(found) and "APP_ENV" not in names(found) and "PATH" not in names(found)
    assert {f.source for f in found} == {"image-config"}


def test_url_credentials_detected_even_with_innocent_name():
    f = [x for x in lf.scan_image_config(CFG) if x.name == "DATABASE_URL"][0]
    assert f.kind == "url-credentials"


def test_docker_inspect_env_and_secret_file_mounts():
    found = lf.scan_docker_inspect(INSPECT)
    assert {"REDIS_PASSWORD", "STRIPE_SECRET"} <= names(found)
    assert "secret-file-bind-mount" in kinds(found)
    assert any(f.name == "/srv/shop/.env" for f in found) and any(f.name.endswith("server.pem") for f in found)


def test_history_finds_env_buildarg_url_file_and_deleted_but_present():
    found = lf.scan_history(HISTORY)
    assert {"secret-in-ENV-layer", "build-arg-secret", "url-credentials", "secret-written-to-file",
            "secret-file-copied", "deleted-but-still-in-layer"} <= kinds(found)
    assert "NPM_TOKEN" in names(found)


def test_history_inside_image_config_is_scanned_too():
    cfg = copy.deepcopy(CFG)
    cfg["history"] = HISTORY
    assert "build-arg-secret" in kinds(lf.scan_image_config(cfg))


def test_evidence_is_always_redacted():
    everything = (lf.scan_image_config(CFG) + lf.scan_docker_inspect(INSPECT) + lf.scan_history(HISTORY)
                  + lf.scan_log(LOG) + lf.scan_compose(COMPOSE))
    assert everything
    for f in everything:
        assert "CANARY-" not in f.evidence, f


def test_log_leaks():
    found = lf.scan_log(LOG)
    assert {"secret-in-log", "bearer-token-in-log", "url-credentials-in-log"} <= kinds(found)
    assert any(f.location == "line 2" and f.name == "DB_PASSWORD" for f in found)


def test_proc_environ_exposes_the_same_secrets():
    data = lf.make_proc_environ(CFG["config"]["Env"])
    assert data.endswith(b"\0") and b"DB_PASSWORD=" in data
    found = lf.scan_proc_environ(data, pid=42)
    assert "DB_PASSWORD" in names(found) and found[0].location.startswith("/proc/42/environ")


def test_compose_findings_before_fix():
    found = lf.scan_compose(COMPOSE)
    assert {"DB_PASSWORD", "API_TOKEN", "SMTP_PASSWORD", "QUEUE_URL"} <= names(found)


def test_runtime_injection_removes_secret_from_env_and_mounts_it():
    clean, mount = lf.runtime_injection(CFG["config"]["Env"])
    assert not lf.scan_env(clean, "x", "y", "HIGH")
    assert "DB_PASSWORD_FILE=/run/secrets/db_password" in clean
    assert mount["db_password"] == "CANARY-db-pass-7f3a"
    assert "SIGNING_KEY_FILE=/run/secrets/signing_key" in clean and "APP_ENV=production" in clean


def test_compose_rewrite_uses_secrets_and_scans_clean():
    fixed, names_ = lf.rewrite_compose(COMPOSE)
    assert lf.scan_compose(fixed) == []
    assert {"db_password", "api_token", "smtp_password", "queue_url"} == set(names_)
    assert fixed["secrets"]["db_password"] == {"file": "./secrets/db_password.txt"}
    assert "db_password" in fixed["services"]["api"]["secrets"]
    assert fixed["services"]["api"]["environment"]["DB_PASSWORD_FILE"] == "/run/secrets/db_password"
    assert fixed["services"]["worker"]["environment"][-1] == "CONCURRENCY=4"  # non-secrets untouched
    # the original document is not modified
    assert COMPOSE["services"]["api"]["environment"]["DB_PASSWORD"].startswith("CANARY")


def test_dumped_fixed_compose_has_no_canary_values():
    import yaml
    fixed, _ = lf.rewrite_compose(COMPOSE)
    assert "CANARY" not in yaml.safe_dump(fixed)


def test_read_secret_prefers_file_and_fails_loudly():
    files = {"/run/secrets/db_password": "s3cr3t-from-file\n"}
    assert lf.read_secret("DB_PASSWORD", {"DB_PASSWORD_FILE": "/run/secrets/db_password"}, files.__getitem__) == "s3cr3t-from-file"
    assert lf.read_secret("DB_PASSWORD", {"DB_PASSWORD": "dev-only"}, files.__getitem__) == "dev-only"
    with pytest.raises(KeyError):
        lf.read_secret("DB_PASSWORD", {}, files.__getitem__)


def test_references_are_not_flagged():
    env = ["DB_PASSWORD=/run/secrets/db_password", "API_TOKEN=${API_TOKEN}", "X_SECRET=vault:kv/app#key", "EMPTY_PASSWORD="]
    assert lf.scan_env(env, "t", "t", "HIGH") == []


def test_clean_text_has_no_findings():
    assert lf.scan_log("INFO started\nINFO listening on :8080\n") == []
    assert lf.scan_history([{"created_by": "/bin/sh -c apt-get update", "empty_layer": False}]) == []
