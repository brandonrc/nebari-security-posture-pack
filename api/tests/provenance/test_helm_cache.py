"""Chart update check caching (grace, 2026-10-05: the provenance stage took 51-193 s with 1-4 images
checked because every scan re-downloaded every chart repo index.yaml and walked unknown charts down
to the Docker Hub tag list).

The index.yaml repo is a real HTTP server on 127.0.0.1 (ETag / Last-Modified / 304 handling goes
through httpx end to end); OCI tag lists go through the in-memory FakeRegistry.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from posture.app_settings import ProvenanceSettings
from posture.config import Settings
from posture.provenance import helm
from posture.provenance.helm import (
    CHECK_DONE,
    CHECK_ERROR,
    CHECK_NOT_CONFIGURED,
    ChartRepos,
    HelmIndexCache,
    HelmRelease,
    check_chart_updates,
)
from posture.provenance.stage import ProvenanceStage

from .fakes import FakeRegistry

INDEX = b"""apiVersion: v1
entries:
  cert-manager:
    - version: v1.17.1
    - version: v1.16.3
    - version: v1.16.2
"""
ETAG = '"idx-v1"'
LAST_MODIFIED = "Sat, 03 Oct 2026 10:00:00 GMT"


class IndexServer:
    """Minimal chart repo: GET /index.yaml with ETag + Last-Modified, 304 on a matching validator."""

    def __init__(self, status: int = 200, etag: str | None = ETAG, last_modified: str | None = LAST_MODIFIED):
        self.requests: list[dict[str, str]] = []
        self.status = status
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.requests.append({"path": self.path, **{k.lower(): v for k, v in self.headers.items()}})
                if outer.status != 200:
                    self.send_response(outer.status)
                    self.send_header("content-length", "0")
                    self.end_headers()
                    return
                if (etag and self.headers.get("If-None-Match") == etag) or (
                        not etag and last_modified and self.headers.get("If-Modified-Since") == last_modified):
                    self.send_response(304)
                    self.end_headers()
                    return
                self.send_response(200)
                if etag:
                    self.send_header("ETag", etag)
                if last_modified:
                    self.send_header("Last-Modified", last_modified)
                self.send_header("content-length", str(len(INDEX)))
                self.end_headers()
                self.wfile.write(INDEX)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/charts"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def clock(monkeypatch):
    now = {"t": 1_790_000_000.0}
    monkeypatch.setattr(helm, "_utcnow", lambda: now["t"])
    return now


def rel(chart="cert-manager", version="v1.16.2", name=None, ns="x"):
    return HelmRelease(name or chart, ns, chart, version, "", "deployed")


async def run(repos, releases, reg=None, max_age_hours=24.0, force=False):
    return await check_chart_updates(releases, repos, skip_prerelease=True, update_level="patch", registry=reg,
                                     max_age_hours=max_age_hours, force=force)


async def test_index_cache_hit_within_ttl_makes_zero_requests(tmp_path, clock):
    with IndexServer() as srv:
        repos = ChartRepos([srv.url], cache=HelmIndexCache(str(tmp_path), ttl_hours=12))
        found = await repos.lookup("cert-manager")
        await repos.aclose()
        assert found.status == CHECK_DONE and "v1.17.1" in found.versions and len(srv.requests) == 1
        assert srv.requests[0]["path"] == "/charts/index.yaml"
        clock["t"] += 11 * 3600
        # a new process: only the on-disk copy under CACHE_DIR/helm-index/ survives
        repos2 = ChartRepos([srv.url], cache=HelmIndexCache(str(tmp_path), ttl_hours=12))
        found2 = await repos2.lookup("cert-manager")
        await repos2.aclose()
        assert found2.versions == found.versions and found2.source == srv.url
        assert len(srv.requests) == 1 and repos2.requests == 0


async def test_index_revalidation_sends_if_none_match(tmp_path, clock):
    with IndexServer() as srv:
        cache = HelmIndexCache(str(tmp_path), ttl_hours=12)
        repos = ChartRepos([srv.url], cache=cache)
        await repos.lookup("cert-manager")
        await repos.aclose()
        assert "if-none-match" not in srv.requests[0]
        clock["t"] += 13 * 3600  # past the TTL
        repos = ChartRepos([srv.url], cache=HelmIndexCache(str(tmp_path), ttl_hours=12))
        found = await repos.lookup("cert-manager")
        await repos.aclose()
        assert len(srv.requests) == 2
        assert srv.requests[1]["if-none-match"] == ETAG
        assert srv.requests[1]["if-modified-since"] == LAST_MODIFIED
        assert found.status == CHECK_DONE and found.versions[0] == "v1.17.1"  # kept from the 304
        clock["t"] += 3600  # the 304 refreshed fetchedAt: fresh again
        repos = ChartRepos([srv.url], cache=HelmIndexCache(str(tmp_path), ttl_hours=12))
        await repos.lookup("cert-manager")
        await repos.aclose()
        assert len(srv.requests) == 2


async def test_index_revalidation_if_modified_since_without_etag(tmp_path, clock):
    with IndexServer(etag=None) as srv:
        repos = ChartRepos([srv.url], cache=HelmIndexCache(str(tmp_path), ttl_hours=1))
        await repos.lookup("cert-manager")
        await repos.aclose()
        clock["t"] += 2 * 3600
        repos = ChartRepos([srv.url], cache=HelmIndexCache(str(tmp_path), ttl_hours=1))
        found = await repos.lookup("cert-manager")
        await repos.aclose()
        assert "if-none-match" not in srv.requests[1]
        assert srv.requests[1]["if-modified-since"] == LAST_MODIFIED and found.status == CHECK_DONE


async def test_stale_index_is_used_when_refresh_fails(tmp_path, clock):
    with IndexServer() as srv:
        repos = ChartRepos([srv.url], cache=HelmIndexCache(str(tmp_path), ttl_hours=1))
        await repos.lookup("cert-manager")
        await repos.aclose()
        srv.status = 503
        clock["t"] += 2 * 3600
        repos = ChartRepos([srv.url], cache=HelmIndexCache(str(tmp_path), ttl_hours=1))
        found = await repos.lookup("cert-manager")
        await repos.aclose()
        assert len(srv.requests) == 2 and found.status == CHECK_DONE and "v1.17.1" in found.versions


async def test_unchanged_releases_make_zero_requests(tmp_path, clock):
    reg = FakeRegistry()
    reg.tags[("quay.io", "nebari/charts/nebari-app")] = ["0.1.0", "0.1.1"]
    with IndexServer() as srv:
        urls = [srv.url, "oci://quay.io/nebari/charts"]

        def repos():  # index TTL 0: only the per-release carry can avoid the requests
            return ChartRepos(urls, cache=HelmIndexCache(str(tmp_path), ttl_hours=0))

        first = [rel(), rel("nebari-app", "0.1.0"), rel("private-chart", "1.0.0")]
        stats = await run(repos(), first, reg)
        assert stats["checked"] == 2 and stats["notConfigured"] == 1 and stats["carried"] == 0
        assert first[0].update.newest_available == "v1.17.1" and first[1].update.newest_available == "0.1.1"
        assert first[2].update_check == CHECK_NOT_CONFIGURED
        n_http, n_reg = len(srv.requests), len(reg.calls)

        clock["t"] += 23 * 3600  # < rescanAfterHours (24)
        second = [rel(), rel("nebari-app", "0.1.0"), rel("private-chart", "1.0.0")]
        r = repos()
        stats = await run(r, second, reg)
        assert (len(srv.requests), len(reg.calls), r.requests) == (n_http, n_reg, 0)
        assert stats == {"checked": 0, "carried": 3, "notConfigured": 0, "errors": 0, "skipped": 0}
        assert [h.as_json() for h in second] == [h.as_json() for h in first]
        assert second[0].chart_source == srv.url and second[1].chart_source == "oci://quay.io/nebari/charts"
        assert second[2].update_check == CHECK_NOT_CONFIGURED

        # a changed version is re-checked; the others still carry
        third = [rel(version="v1.17.1"), rel("nebari-app", "0.1.0"), rel("private-chart", "1.0.0")]
        stats = await run(repos(), third, reg)
        assert (stats["checked"], stats["carried"]) == (1, 2) and third[0].update is None
        assert len(srv.requests) == n_http + 1

        # older than rescanAfterHours: everything is re-checked
        clock["t"] += 25 * 3600
        stats = await run(repos(), [rel(), rel("nebari-app", "0.1.0")], reg)
        assert (stats["checked"], stats["carried"]) == (2, 0)


async def test_forced_or_reconfigured_check_does_not_carry(tmp_path, clock):
    with IndexServer() as srv:
        cache = HelmIndexCache(str(tmp_path), ttl_hours=0)
        await run(ChartRepos([srv.url], cache=cache), [rel()])
        assert (await run(ChartRepos([srv.url], cache=cache), [rel()], force=True))["checked"] == 1
        other = ChartRepos([srv.url, "https://charts.example.invalid"], cache=cache)  # different repo list
        assert (await run(other, [rel()]))["carried"] == 0


async def test_errors_are_not_carried(tmp_path, clock):
    with IndexServer(status=500) as srv:
        cache = HelmIndexCache(str(tmp_path), ttl_hours=12)
        r = [rel()]
        stats = await run(ChartRepos([srv.url], cache=cache), r)
        assert stats["errors"] == 1 and r[0].update_check == CHECK_ERROR and r[0].update is None
        srv.status = 200
        r = [rel()]
        stats = await run(ChartRepos([srv.url], cache=cache), r)
        assert stats["checked"] == 1 and r[0].update.newest_available == "v1.17.1" and len(srv.requests) == 2


async def test_unknown_chart_makes_zero_docker_hub_requests(tmp_path, clock):
    reg = FakeRegistry()
    reg.tags[("docker.io", "envoyproxy/gateway-helm")] = ["v1.2.0", "v1.2.1"]
    with IndexServer() as srv:
        urls = [srv.url, "oci://quay.io/nebari/charts", "oci://docker.io/envoyproxy",
                "oci://docker.io/envoyproxy/gateway-helm"]
        r = [rel("artifact-keeper", "0.3.0"), rel("security-posture", "0.1.0"), rel("gateway-helm", "v1.2.0")]
        stats = await run(ChartRepos(urls, cache=HelmIndexCache(str(tmp_path), ttl_hours=12)), r, reg)
    hub = [c for c in reg.calls if c[1] in helm.DOCKER_HUB_HOSTS]
    # the Docker Hub *prefix* is never probed; the explicit chart reference is
    assert hub == [("tags", "docker.io", "envoyproxy/gateway-helm")]
    assert [x.update_check for x in r] == [CHECK_NOT_CONFIGURED, CHECK_NOT_CONFIGURED, CHECK_DONE]
    assert r[2].update.newest_available == "v1.2.1" and r[2].chart_source == "oci://docker.io/envoyproxy/gateway-helm"
    assert stats["notConfigured"] == 2
    # the non-Hub prefix was asked once per chart (it comes first) and its "not found" is cached on disk
    quay = [c for c in reg.calls if c[1] == "quay.io"]
    assert len(quay) == 3
    again = ChartRepos(urls, cache=HelmIndexCache(str(tmp_path), ttl_hours=12))
    assert (await again.lookup("artifact-keeper", reg)).status == CHECK_NOT_CONFIGURED
    assert len(reg.calls) == len(quay) + len(hub) and again.requests == 0


def test_oci_candidates():
    c = ChartRepos.oci_candidate
    assert c("oci://quay.io/nebari/charts", "nebari-app") == ("quay.io", "nebari/charts/nebari-app")
    assert c("oci://ghcr.io/org/thing", "thing") == ("ghcr.io", "org/thing")
    assert c("oci://docker.io/envoyproxy", "gateway-helm") is None
    assert c("oci://registry-1.docker.io/bitnamicharts", "redis") is None
    assert c("oci://docker.io/bitnamicharts/redis", "redis") == ("docker.io", "bitnamicharts/redis")


async def test_stage_helm_timing_and_carry(tmp_path, clock):
    async def discover(excluded):
        return [rel()], []

    with IndexServer() as srv:
        env = Settings(cache_dir=str(tmp_path), provenance_helm_chart_repos=[srv.url])
        stage = ProvenanceStage(env, None, helm_discover=discover)
        ps = ProvenanceSettings()
        timing, stats = {}, {}
        rows, errors = await stage._helm(ps, FakeRegistry(), 24.0, False, timing, stats)
        assert (tmp_path / "helm-index" / "checks.json").exists()
        assert set(timing) == {"helm_discovery_ms", "helm_updates_ms"} and not errors
        assert stats["checked"] == 1 and stats["requests"] == 1 and rows[0].update.update_available
        # next scan (new worker process, same CACHE_DIR): carried, no request
        stage = ProvenanceStage(env, None, helm_discover=discover)
        timing, stats = {}, {}
        rows, _ = await stage._helm(ps, FakeRegistry(), 24.0, False, timing, stats)
        assert stats["carried"] == 1 and stats["requests"] == 0 and len(srv.requests) == 1
        assert rows[0].update.newest_available == "v1.17.1"
