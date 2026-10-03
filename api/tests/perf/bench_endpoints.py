"""Before/after timings of /vulnerabilities and /images/{id} on the gen_dataset.py data (not CI).

    PERF_DATABASE_URL=postgresql://u:p@host/perf python tests/perf/bench_endpoints.py [--old-rev REV]

"before" = the in-Python implementations: /vulnerabilities with the scan's rollup marker
cleared (the fallback is the old grouping code), /images/{id} from routers/images.py at
`--old-rev` (default: the commit before the SQL pagination). Reports the median wall time of 5
calls, the peak Python allocation (tracemalloc) and the JSON size, handler only (no HTTP).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import subprocess
import sys
import time
import tracemalloc
import types


def load_old_images_router(rev: str):
    src = subprocess.run(["git", "show", f"{rev}:api/src/posture/routers/images.py"], capture_output=True,
                         text=True, check=True).stdout
    mod = types.ModuleType("posture.routers._old_images")
    mod.__package__ = "posture.routers"
    sys.modules[mod.__name__] = mod
    exec(compile(src, "old_images.py", "exec"), mod.__dict__)
    return mod


async def measure(label, fn, runs=5):
    times = []
    for _ in range(runs):
        tracemalloc.start()
        t = time.perf_counter()
        out = await fn()
        times.append(time.perf_counter() - t)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    size = len(json.dumps(out, default=str))
    print(f"{label:58s} {statistics.median(times) * 1000:9.1f} ms   peak {peak / 2**20:7.1f} MiB   json {size / 1024:8.1f} KiB")
    return out


async def main(rev: str) -> None:
    os.environ["DATABASE_URL"] = os.environ["PERF_DATABASE_URL"]
    from sqlalchemy import func, select, update

    from posture.config import get_settings

    get_settings.cache_clear()
    from posture.db.models import ConsensusFindingRow, Scan
    from posture.db.session import dispose_engine, get_sessionmaker
    from posture.routers import images as new_images
    from posture.routers import vulnerabilities as v

    old_images = load_old_images_router(rev)
    sm = get_sessionmaker()
    async with sm() as s:
        img_id, n = (await s.execute(select(ConsensusFindingRow.image_id, func.count()).group_by(
            ConsensusFindingRow.image_id).order_by(func.count().desc()).limit(1))).one()
        scan = (await s.execute(select(Scan).order_by(Scan.id.desc()).limit(1))).scalar_one()
        rolled_at = scan.vuln_rollup_at
    print(f"image {img_id}: {n} findings")

    def vulns(**kw):
        args = dict(severity=None, q=None, fixable=None, kev=None, sort="severity", order="desc", page=1,
                    pageSize=50, cursor=None)
        args.update(kw)

        async def call():
            async with sm() as s:
                return await v.list_vulns(session=s, **args)
        return call

    def new_image(**kw):
        args = dict(page=None, pageSize=50, severity=None, q=None, fixable=None, disagree=None, sort="severity",
                    order="desc")
        args.update(kw)

        async def call():
            async with sm() as s:
                return await new_images.get_image(img_id, session=s, **args)
        return call

    async def old_image():
        async with sm() as s:
            return await old_images.get_image(img_id, session=s)

    print("--- after (vuln_rollup / SQL pagination)")
    first = await measure("/vulnerabilities page 1", vulns())
    await measure("/vulnerabilities page 100", vulns(page=100))
    await measure("/vulnerabilities q=lib12", vulns(q="lib12"))
    await measure("/vulnerabilities sort=imagesAffected", vulns(sort="imagesAffected"))
    await measure("/vulnerabilities keyset (nextCursor of page 1)", vulns(cursor=first["nextCursor"]))
    await measure(f"/images/{{id}} page=1 pageSize=50", new_image(page=1))
    await measure("/images/{id} no page (first 500, truncated)", new_image())
    await measure("/images/{id} page=1 q=lib1 fixable", new_image(page=1, q="lib1", fixable=True))
    print("--- before (Python grouping / unpaginated)")
    async with sm() as s, s.begin():
        await s.execute(update(Scan).where(Scan.id == scan.id).values(vuln_rollup_at=None))
    try:
        await measure("/vulnerabilities page 1", vulns(), runs=3)
        await measure("/vulnerabilities q=lib12", vulns(q="lib12"), runs=3)
    finally:
        async with sm() as s, s.begin():
            await s.execute(update(Scan).where(Scan.id == scan.id).values(vuln_rollup_at=rolled_at))
    await measure("/images/{id} (all findings)", old_image, runs=3)
    await dispose_engine()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-rev", default="430bbfe^")
    asyncio.run(main(ap.parse_args().old_rev))
