import re

from cyllex_argus.web.app import DEFAULT_STATIC_DIR
from tests.web.conftest import make_client

INDEX = DEFAULT_STATIC_DIR / "index.html"
SCRIPT_TAG = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.IGNORECASE | re.DOTALL)
ASSET_REF = re.compile(r"""(?:src|href)="(/assets/[^"]+)\"""")
REMOTE_ATTR = re.compile(r"""(?:src|href)=["']?(?:https?:)?//""", re.IGNORECASE)
REMOTE_CSS = re.compile(r"""(?:url\(\s*["']?|@import\s+["'])(?:https?:)?//""", re.IGNORECASE)


def test_the_committed_build_exists():
    assert INDEX.is_file(), "run `npm run build` in web/ and commit src/cyllex_argus/web/static"
    assets = list((DEFAULT_STATIC_DIR / "assets").iterdir())
    assert any(p.suffix == ".js" for p in assets)
    assert any(p.suffix == ".css" for p in assets)


def test_index_has_no_inline_scripts_and_no_remote_resources():
    html = INDEX.read_text(encoding="utf-8")
    scripts = SCRIPT_TAG.findall(html)
    assert scripts, "the entry script tag is missing"
    for attributes, body in scripts:
        assert 'src="/assets/' in attributes
        assert body.strip() == ""
    assert not REMOTE_ATTR.search(html)
    assert '<div id="root"></div>' in html


def test_built_css_loads_nothing_remote():
    for css in (DEFAULT_STATIC_DIR / "assets").glob("*.css"):
        assert not REMOTE_CSS.search(css.read_text(encoding="utf-8")), css.name


def test_the_backend_serves_the_built_app_with_correct_types(world):
    client = make_client(world, static_dir=DEFAULT_STATIC_DIR)
    index = client.get("/")
    assert index.status_code == 200
    assert index.headers["content-type"].startswith("text/html")
    assert index.headers["content-security-policy"].startswith("default-src 'self'")
    refs = ASSET_REF.findall(index.text)
    assert refs
    for ref in refs:
        asset = client.get(ref)
        assert asset.status_code == 200, ref
        expected = "text/javascript" if ref.endswith(".js") else "text/css" if ref.endswith(".css") else ""
        assert asset.headers["content-type"].startswith(expected), (ref, asset.headers["content-type"])
    deep = client.get("/threats/intrusion-set--00000000-0000-4000-8000-000000001015")
    assert deep.status_code == 200 and '<div id="root"></div>' in deep.text
    assert client.get("/assets/missing-file.js").status_code == 404


def test_every_built_asset_is_served_with_its_type_including_lazy_chunks(world):
    # index.html only names the entry files; code-split chunks (the relationship graph) are imported at runtime.
    client = make_client(world, static_dir=DEFAULT_STATIC_DIR)
    expected_types = {".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg"}
    files = [p for p in (DEFAULT_STATIC_DIR / "assets").iterdir() if p.is_file()]
    assert sum(p.suffix == ".js" for p in files) > 1, "expected the entry bundle plus a lazily loaded chunk"
    for path in files:
        response = client.get(f"/assets/{path.name}")
        assert response.status_code == 200, path.name
        expected = expected_types.get(path.suffix)
        assert expected is not None, f"unexpected asset type in the build: {path.name}"
        assert response.headers["content-type"].startswith(expected), (path.name, response.headers["content-type"])
        assert response.content == path.read_bytes(), path.name
    favicon = client.get("/favicon.svg")
    assert favicon.status_code == 200 and favicon.headers["content-type"].startswith("image/svg+xml")
    # Raster favicons shipped as a 3-file set (same filenames Cyllex ships, so the tab icon
    # matches that framework). If a future vite config drops them from the build output this
    # catches it before it ships.
    for name, mime in (("favicon.ico", "image/"), ("favicon.png", "image/png"),
                       ("favicon-256.png", "image/png")):
        response = client.get(f"/{name}")
        assert response.status_code == 200, name
        assert response.headers["content-type"].startswith(mime), (name, response.headers["content-type"])


def test_js_is_served_as_javascript_even_if_the_registry_says_otherwise(world, tmp_path, monkeypatch):
    import mimetypes

    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text('<div id="root"></div>', encoding="utf-8")
    (static / "assets" / "app.js").write_text("export {}", encoding="utf-8")
    (static / "assets" / "font.woff2").write_bytes(b"wOF2")
    monkeypatch.setitem(mimetypes.types_map, ".js", "text/plain")
    client = make_client(world, static_dir=static)
    assert client.get("/assets/app.js").headers["content-type"].startswith("text/javascript")
    assert client.get("/assets/font.woff2").headers["content-type"] == "font/woff2"
