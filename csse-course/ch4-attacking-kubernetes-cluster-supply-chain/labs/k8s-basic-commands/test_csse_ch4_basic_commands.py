from pathlib import Path

import pytest
from aisec_lab import load_lab_module

mt = load_lab_module(__file__, "manifest_tools")
DOCS = mt.load_all((Path(__file__).parent / "fixtures/app.yaml").read_text())


def test_get_table_filters_kind_and_namespace():
    rows = mt.get_table(DOCS, "Deployment", "shop")
    assert [r[1] for r in rows] == ["web", "api"] and rows[0][2] == "replicas=3"
    assert mt.get_table(DOCS, "deployment", "other") == []
    assert mt.get_table(DOCS, "service")[0][2] == "type=ClusterIP"


def test_jsonpath_with_index_and_missing_paths():
    assert mt.jsonpath(DOCS[1], "spec.template.spec.containers[0].image") == "nginx:1.27"
    assert mt.jsonpath(DOCS[1], "spec.template.spec.containers[9].image") is None
    assert mt.jsonpath(DOCS[1], "spec.nope.x") is None


def test_images_include_init_containers():
    imgs = dict((w + i, i) for w, i in mt.images(DOCS))
    assert "registry.corp.example/shop/api:1.4" in imgs.values()
    assert len([1 for w, _ in mt.images(DOCS) if w == "Deployment/api"]) == 2


def test_missing_limits():
    assert mt.missing_limits(DOCS) == ["Deployment/web:sidecar", "Deployment/api:api"]


def test_describe_shows_labels():
    assert "app=web, tier=frontend" in mt.describe(DOCS[1])


def test_invalid_document_is_rejected():
    with pytest.raises(ValueError):
        mt.load_all("foo: bar")


def test_safe_load_refuses_python_object_tags():
    import yaml
    with pytest.raises(yaml.YAMLError):
        mt.load_all("!!python/object/apply:os.getcwd []")
