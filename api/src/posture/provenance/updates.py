"""Image / chart update check (DESIGN §12), a port of provenance-collector-pack
`internal/registry/updates.go` including Masterminds/semver v3 (`NewVersion`)
parsing and ordering, so `latestInMajor` / `newestAvailable` / `updateAvailable`
match theirs for the same tag list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

UPDATE_LEVEL_PATCH = "patch"  # flag patch, minor and major (default)
UPDATE_LEVEL_MINOR = "minor"  # flag minor and major only
UPDATE_LEVEL_MAJOR = "major"  # flag major only
UPDATE_LEVELS = (UPDATE_LEVEL_PATCH, UPDATE_LEVEL_MINOR, UPDATE_LEVEL_MAJOR)

# Masterminds/semver v3 loose regex (NewVersion with coercion): optional "v", one to
# three numeric segments, optional prerelease and build metadata.
_SEMVER_RE = re.compile(
    r"^v?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?"
    r"(?:-([0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*))?"
    r"(?:\+([0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*))?$"
)
_MAX_U64 = 2**64 - 1


class InvalidVersion(ValueError):
    pass


@total_ordering
@dataclass(frozen=True, eq=False)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: str
    metadata: str
    original: str

    @classmethod
    def parse(cls, s: str) -> Version:
        m = _SEMVER_RE.match(s or "")
        if not m:
            raise InvalidVersion(f"invalid semantic version: {s!r}")
        nums = []
        for g in m.group(1, 2, 3):
            n = int(g) if g is not None else 0
            if n > _MAX_U64:
                raise InvalidVersion(f"version segment out of range: {s!r}")
            nums.append(n)
        pre = m.group(4) or ""
        # semver 2.0: numeric prerelease identifiers must not have leading zeros
        for part in pre.split(".") if pre else []:
            if part.isdigit() and len(part) > 1 and part.startswith("0"):
                raise InvalidVersion(f"invalid prerelease {pre!r}")
        return cls(nums[0], nums[1], nums[2], pre, m.group(5) or "", s)

    def compare(self, other: Version) -> int:
        for a, b in ((self.major, other.major), (self.minor, other.minor), (self.patch, other.patch)):
            if a != b:
                return 1 if a > b else -1
        if self.prerelease == other.prerelease:
            return 0
        if self.prerelease == "":
            return 1
        if other.prerelease == "":
            return -1
        return _compare_prerelease(self.prerelease, other.prerelease)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self.compare(other) == 0

    def __lt__(self, other: Version) -> bool:
        return self.compare(other) < 0

    def __hash__(self) -> int:
        return hash((self.major, self.minor, self.patch, self.prerelease))

    def greater_than(self, other: Version) -> bool:
        return self.compare(other) > 0


def _compare_pre_part(s: str, o: str) -> int:
    if s == o:
        return 0
    if s == "":
        return -1 if o != "" else 1
    if o == "":
        return 1 if s != "" else -1
    s_num, o_num = s.isdigit(), o.isdigit()
    if not s_num and not o_num:
        return 1 if s > o else -1
    if not o_num:  # numeric < alphanumeric
        return -1
    if not s_num:
        return 1
    return 1 if int(s) > int(o) else -1


def _compare_prerelease(a: str, b: str) -> int:
    sp, op = a.split("."), b.split(".")
    for i in range(max(len(sp), len(op))):
        d = _compare_pre_part(sp[i] if i < len(sp) else "", op[i] if i < len(op) else "")
        if d:
            return d
    return 0


def parse_version(s: str) -> Version | None:
    try:
        return Version.parse(s)
    except InvalidVersion:
        return None


@dataclass
class UpdateInfo:
    current_tag: str
    latest_in_major: str = ""
    newest_available: str = ""
    update_available: bool = False

    def as_json(self) -> dict[str, object]:
        """Their UpdateInfo JSON (omitempty on latestInMajor / newestAvailable)."""
        out: dict[str, object] = {"currentTag": self.current_tag}
        if self.latest_in_major:
            out["latestInMajor"] = self.latest_in_major
        if self.newest_available:
            out["newestAvailable"] = self.newest_available
        out["updateAvailable"] = self.update_available
        return out

    @classmethod
    def from_json(cls, d: dict | None) -> UpdateInfo | None:
        if not d:
            return None
        return cls(d.get("currentTag") or "", d.get("latestInMajor") or "", d.get("newestAvailable") or "",
                   bool(d.get("updateAvailable")))

    @property
    def major_behind(self) -> bool:
        cur = parse_version(self.current_tag)
        new = parse_version(self.newest_available) if self.newest_available else None
        return bool(self.update_available and cur and new and new.major > cur.major)


def parse_image_ref(ref: str) -> tuple[str, str]:
    """Their parseImageRef: split into (repository, tag); digest refs have tag ""."""
    if "@" in ref:
        return ref.split("@", 1)[0], ""
    last_colon = ref.rfind(":")
    last_slash = ref.rfind("/")
    if last_colon > last_slash and last_colon != -1:
        return ref[:last_colon], ref[last_colon + 1:]
    return ref, "latest"


def should_flag(current: Version, info: UpdateInfo, update_level: str) -> bool:
    for raw in (info.latest_in_major, info.newest_available):
        if not raw:
            continue
        v = parse_version(raw)
        if v is None or not v.greater_than(current):
            continue
        if update_level == UPDATE_LEVEL_MAJOR:
            if v.major != current.major:
                return True
        elif update_level == UPDATE_LEVEL_MINOR:
            if v.major != current.major or v.minor != current.minor:
                return True
        else:
            return True
    return False


def compute_update(tag: str, available_tags: list[str] | None, *, skip_prerelease: bool = True,
                   update_level: str = UPDATE_LEVEL_PATCH) -> UpdateInfo:
    """Their RegistryUpdateChecker.Check minus the network call.

    `available_tags` None means "not listed" (latest / non-semver tags short-circuit
    before listing, exactly like theirs)."""
    update_level = update_level or UPDATE_LEVEL_PATCH
    if tag in ("", "latest"):
        return UpdateInfo(current_tag=tag)
    current = parse_version(tag)
    if current is None:
        return UpdateInfo(current_tag=tag)
    versions = []
    for t in available_tags or []:
        v = parse_version(t)
        if v is None:
            continue
        if skip_prerelease and v.prerelease:
            continue
        versions.append(v)
    versions.sort()
    info = UpdateInfo(current_tag=tag)
    for v in reversed(versions):
        if v.major == current.major and v.greater_than(current):
            info.latest_in_major = v.original
            break
    if versions and versions[-1].greater_than(current):
        info.newest_available = versions[-1].original
    info.update_available = should_flag(current, info, update_level)
    return info


def needs_tag_list(tag: str) -> bool:
    """False when the update check short-circuits without listing tags."""
    return tag not in ("", "latest") and parse_version(tag) is not None
