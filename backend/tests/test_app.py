from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def make_client(tmp_path, with_frontend: bool) -> TestClient:
    static = tmp_path / "static"
    if with_frontend:
        (static / "assets").mkdir(parents=True)
        (static / "index.html").write_text("<html>magma</html>")
        (static / "assets" / "app.js").write_text("console.log(1)")
        (static / "favicon.svg").write_text("<svg></svg>")
    return TestClient(
        create_app(
            Settings(
                static_dir=static,
                database_url=f"sqlite:///{tmp_path}/t.db",
                admin_password="x" * 12,
            )
        )
    )


def test_health(tmp_path):
    r = make_client(tmp_path, False).get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_version(tmp_path):
    r = make_client(tmp_path, False).get("/api/version")
    assert r.status_code == 200
    assert r.json()["version"]


def test_spa_fallback_and_assets(tmp_path):
    client = make_client(tmp_path, True)
    assert client.get("/").text == "<html>magma</html>"
    assert client.get("/usecases/AO-CRE").text == "<html>magma</html>"
    assert client.get("/assets/app.js").text == "console.log(1)"
    assert client.get("/favicon.svg").text == "<svg></svg>"


def test_unknown_api_path_is_404(tmp_path):
    assert make_client(tmp_path, True).get("/api/nope").status_code == 404


def test_no_path_traversal(tmp_path):
    (tmp_path / "secret.txt").write_text("secret")
    r = make_client(tmp_path, True).get("/..%2Fsecret.txt")
    assert "secret" not in r.text


def test_built_assets_are_cached_and_the_page_is_revalidated(tmp_path):
    client = make_client(tmp_path, True)
    assert "immutable" in client.get("/assets/app.js").headers["cache-control"]
    assert client.get("/").headers["cache-control"] == "no-cache"
    assert client.get("/usecases").headers["cache-control"] == "no-cache"


def test_large_answers_are_compressed(admin):
    r = admin.get("/api/l3", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200 and r.headers.get("content-encoding") == "gzip"
    assert "cache-control" not in r.headers or "immutable" not in r.headers["cache-control"]
    small = admin.get("/api/health", headers={"Accept-Encoding": "gzip"})
    assert "content-encoding" not in small.headers
