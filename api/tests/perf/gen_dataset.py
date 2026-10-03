"""Synthetic dataset for the list-endpoint benchmarks (architecture review M4). Not run in CI
(no `test_` prefix).

    PERF_DATABASE_URL=postgresql://u:p@host/perf python tests/perf/gen_dataset.py [--images 500]

Drops and recreates the schema of PERF_DATABASE_URL, migrates to head, then writes one done
scan with N images (default 500), ~360 consensus findings per image (~180k rows, as measured
on the lab cluster: 28k rows for 79 images) drawn from a pool of 20k CVEs with a long-tail
distribution, 1-3 workloads per image across 60 namespaces, and the scan's cluster snapshot
and vuln_rollup (what the worker writes at scan end).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import random
from datetime import UTC, datetime, timedelta

SEVS = ["critical", "high", "medium", "low", "negligible", "unknown"]
SEV_W = [3, 15, 40, 30, 8, 4]
SCANNER_SETS = [["trivy", "grype", "clair"], ["trivy", "grype"], ["trivy", "clair"], ["grype"], ["trivy"],
                ["grype", "clair"]]
SET_W = [42, 17, 20, 8, 8, 5]


async def generate(url: str, n_images: int = 500, per_image: int = 360, seed: int = 7) -> int:
    from alembic import command
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from posture.config import Settings
    from posture.db.models import ConsensusFindingRow, ContainerRow, Image, Scan, ScanSnapshot, WorkloadRow
    from posture.migrate import alembic_config
    from posture.rollup import write_vuln_rollup

    rnd = random.Random(seed)
    dburl = Settings(database_url=url).database_url
    eng = create_async_engine(dburl)
    async with eng.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
    os.environ["DATABASE_URL"] = url
    from posture.config import get_settings

    get_settings.cache_clear()
    await asyncio.to_thread(command.upgrade, alembic_config(), "head")
    sm = async_sessionmaker(eng, expire_on_commit=False)
    now = datetime.now(UTC)
    pool = [f"CVE-{2015 + i % 11}-{10000 + i}" for i in range(20000)]
    weights = [1 / (1 + i) ** 0.6 for i in range(len(pool))]
    pkgs = [f"lib{n}" for n in range(1500)]
    async with sm() as s, s.begin():
        scan = Scan(trigger="scheduled", status="done", started_at=now - timedelta(minutes=30), finished_at=now,
                    images_total=n_images, images_done=n_images, per_scanner={}, log=[], inventory_complete=True,
                    score=61.0, grade="D")
        s.add(scan)
        await s.flush()
        sid = scan.id
        imgs = []
        for i in range(n_images):
            digest = "sha256:" + f"{i:064x}"
            imgs.append(Image(key=f"registry.example/team{i % 40}/app{i}@{digest}", ref=f"registry.example/team{i % 40}/app{i}:1.{i}",
                              registry_host="registry.example", repository=f"team{i % 40}/app{i}", tag=f"1.{i}",
                              tags=[f"1.{i}"], digest=digest, score=rnd.uniform(20, 99), grade="C", counts={},
                              fixable={}, scanners={n: {"status": "ok"} for n in ("trivy", "grype", "clair")},
                              namespaces=[f"ns{i % 60}"], workloads=1, containers=2, running=True,
                              warnings=[], last_scanned_at=now, last_scan_id=sid))
        s.add_all(imgs)
        await s.flush()
        conts, wls = [], []
        for idx, img in enumerate(imgs):
            for w in range(1 + idx % 3):
                ns = f"ns{(idx + w) % 60}"
                conts.append({"scan_id": sid, "namespace": ns, "pod": f"p{idx}-{w}", "container": "c",
                              "container_type": "container", "image": img.ref, "image_fk": img.id,
                              "workload_kind": "Deployment", "workload_name": f"wl{idx}-{w}", "running": True,
                              "security": {}})
                wls.append({"scan_id": sid, "namespace": ns, "kind": "Deployment", "name": f"wl{idx}-{w}",
                            "grade": "C", "image_ids": [img.id], "counts": {}})
        await s.execute(ContainerRow.__table__.insert(), conts)
        await s.execute(WorkloadRow.__table__.insert(), wls)
        total = 0
        for img in imgs:
            n = max(5, int(rnd.gauss(per_image, per_image / 2)))
            vids = set(rnd.choices(pool, weights=weights, k=n))
            rows, counts, fixable = [], dict.fromkeys(SEVS, 0), dict.fromkeys(SEVS, 0)
            for vid in vids:
                sev = rnd.choices(SEVS, SEV_W)[0]
                sc = rnd.choices(SCANNER_SETS, SET_W)[0]
                fx = rnd.random() < 0.6
                counts[sev] += 1
                fixable[sev] += int(fx)
                rows.append({"image_id": img.id, "scan_id": sid, "vuln_id": vid, "package": rnd.choice(pkgs),
                             "installed_version": "1.0", "fixed_version": "1.1" if fx else None, "pkg_type": "deb",
                             "severity": sev, "scanners": sc, "per_scanner": {x: sev for x in sc},
                             "agreement": len(sc) / 3, "cvss": round(rnd.uniform(1, 10), 1),
                             "title": f"{vid} in a package", "url": f"https://nvd.nist.gov/vuln/detail/{vid}",
                             "fixable": fx, "first_seen_at": now - timedelta(days=rnd.randint(0, 200)),
                             "last_seen_at": now})
            await s.execute(ConsensusFindingRow.__table__.insert(), rows)
            img.counts, img.fixable = counts, fixable
            total += len(rows)
        await s.flush()
        top = sorted(imgs, key=lambda i: i.score)[:10]
        agg = dict.fromkeys(SEVS, 0)
        agg_fx = dict.fromkeys(SEVS, 0)
        for i in imgs:
            for k in SEVS:
                agg[k] += i.counts[k]
                agg_fx[k] += i.fixable[k]
        s.add(ScanSnapshot(scan_id=sid, level="cluster", key="", score=61.0, grade="D", data={
            "counts": agg, "fixable": agg_fx, "topRisks": [
                {"imageId": i.id, "ref": i.ref, "score": i.score, "grade": i.grade, "critical": i.counts["critical"],
                 "high": i.counts["high"], "workloads": i.workloads} for i in top]}))
        rolled = await write_vuln_rollup(s, sid)
    async with eng.begin() as conn:
        await conn.execute(text("ANALYZE"))
    await eng.dispose()
    print(f"scan {sid}: {n_images} images, {total} consensus findings, {rolled} vulnerabilities")
    return sid


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--images", type=int, default=500)
    ap.add_argument("--per-image", type=int, default=360)
    a = ap.parse_args()
    asyncio.run(generate(os.environ["PERF_DATABASE_URL"], a.images, a.per_image))
