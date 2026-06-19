#!/usr/bin/env python3
"""Safe two-phase directory cleanup: scan to manifest, then delete from manifest.

A defensive replacement for ``rm -rf`` over aged data directories. Instead of
deleting in a single command, the workflow is split so the user sees and
approves the exact list of paths before anything is removed.

Workflow
--------
1. ``scan`` walks every immediate subdirectory of ``root``, gathers
   per-directory metadata, decides which ones predate ``--cutoff``, and
   writes the result to a JSON manifest.
2. (manual review) — open the manifest and confirm the candidate list.
3. ``delete`` re-reads the manifest and removes each listed directory, but
   only when ``--confirm`` is passed.

Notes
-----
Safety rules:

* A directory is only eligible if its *newest contained file* is older
  than the cutoff. A single recently-touched file anywhere in the tree
  protects the whole directory.
* Empty directories fall back to their own ``st_mtime``.
* ``delete`` re-checks that each path still exists and is still a
  directory, so the manifest going stale between phases is harmless.
* ``delete`` refuses to run without ``--confirm``.

Exit codes:

* ``0`` — scan completed or delete finished normally.
* Non-zero — ``argparse`` rejected the command line, ``--confirm`` was
  omitted on ``delete``, or an unhandled OS error propagated.

Examples
--------
Scan a directory and emit a manifest::

    python cleanup_files_older_than.py scan /data/models \\
        --cutoff 2025-01-01 --out old_models.json

Force a specific platform's metadata schema (useful for remote mounts)::

    python cleanup_files_older_than.py scan /data/models \\
        --cutoff 2025-01-01 --platform mac

Delete the directories listed by a prior scan::

    python cleanup_files_older_than.py delete old_models.json --confirm
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat as stat_mod
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional


def parse_date(date_str: str) -> float:
    """Convert a ``YYYY-MM-DD`` string into a POSIX timestamp.

    The returned value is comparable to ``os.stat_result.st_mtime``. The date
    is interpreted in the local timezone — the same frame ``st_mtime`` is
    rendered in — so cutoff comparisons stay consistent on a single host.

    Parameters
    ----------
    date_str : str
        Calendar date in ISO ``YYYY-MM-DD`` form. Any time portion is
        rejected.

    Returns
    -------
    float
        Seconds since the Unix epoch for midnight on ``date_str``.

    Raises
    ------
    ValueError
        If ``date_str`` does not match ``YYYY-MM-DD``.
    """
    return datetime.strptime(date_str, "%Y-%m-%d").timestamp()


def resolve_platform(platform_arg: str) -> str:
    """Return the canonical platform name used by the rest of the script.

    The script collects different metadata fields per OS, so every code path
    needs a single normalized identifier. Passing an explicit value (rather
    than ``"auto"``) lets callers override detection — useful when scanning
    a remotely-mounted share that was written by a different OS than the
    one currently running the script.

    Parameters
    ----------
    platform_arg : str
        One of ``"auto"``, ``"mac"``, ``"linux"``, ``"windows"``.
        ``"auto"`` triggers detection from ``sys.platform``.

    Returns
    -------
    str
        One of ``"mac"``, ``"linux"``, ``"windows"``. Any unrecognized host
        ``sys.platform`` value is treated as ``"linux"`` because it covers
        all other POSIX systems the ``pwd`` module supports.
    """
    if platform_arg != "auto":
        return platform_arg
    # Dict lookup avoids static-analysis false positives from if/elif narrowing
    # on sys.platform's literal type.
    return {"darwin": "mac", "win32": "windows"}.get(sys.platform, "linux")


def owner_name(path: Path, platform: str) -> str:
    """Return the human-readable file owner for ``path``.

    The lookup mechanism differs per OS:

    * ``mac`` / ``linux``: resolves the UID via ``pwd.getpwuid``.
    * ``windows``: queries ``win32security`` (requires ``pip install pywin32``)
      and returns ``"DOMAIN\\name"``.

    Any failure — missing UID, denied ACL read, ``pywin32`` not installed —
    is swallowed and reported as ``"unknown"`` so a single unresolvable file
    cannot abort the surrounding scan.

    Parameters
    ----------
    path : pathlib.Path
        File or directory whose owner should be looked up.
    platform : str
        Canonical platform name from :func:`resolve_platform`.

    Returns
    -------
    str
        Owner name (e.g. ``"daniel"``, ``"BUILTIN\\Administrators"``), or
        ``"unknown"`` if the lookup failed for any reason.
    """
    if platform == "windows":
        try:
            import win32security  # type: ignore[import-untyped]  # pip install pywin32 (Windows only)
            sd = win32security.GetFileSecurity(
                str(path), win32security.OWNER_SECURITY_INFORMATION
            )
            sid = sd.GetSecurityDescriptorOwner()
            name, domain, _ = win32security.LookupAccountSid(None, sid)
            return f"{domain}\\{name}"
        except Exception:
            return "unknown"
    else:
        try:
            from pwd import getpwuid
            return getpwuid(path.stat().st_uid).pw_name
        except Exception:
            return "unknown"


def _ts(ts: float) -> str:
    """Format a POSIX timestamp as a local-time ISO-8601 string.

    Used exclusively to add ``*_readable`` fields next to raw timestamps in
    the JSON manifest so a human can skim it without parsing epoch seconds.

    Parameters
    ----------
    ts : float
        Seconds since the Unix epoch.

    Returns
    -------
    str
        ISO-8601 string such as ``"2024-01-01T00:00:00"``, in the local
        timezone (no offset suffix).
    """
    return datetime.fromtimestamp(ts).isoformat()


def _dir_platform_meta(s: os.stat_result, platform: str) -> dict:
    """Build the platform-specific fields appended to a directory record.

    Each OS exposes a different set of timestamps and attributes, and the
    same ``st_*`` field can mean different things across platforms — most
    notably ``st_ctime``, which is *metadata change time* on Unix but
    *creation time* on Windows. The dict returned here normalizes those
    differences so downstream consumers can read consistent field names
    regardless of the source OS.

    Parameters
    ----------
    s : os.stat_result
        Stat result for the directory being recorded.
    platform : str
        Canonical platform name from :func:`resolve_platform`.

    Returns
    -------
    dict
        Platform-specific fields ready to merge into the JSON entry produced
        by :func:`scan_candidate_dir`. Empty for an unknown platform.

    Notes
    -----
    Per-platform fields:

    * ``mac``:
        - ``birthtime`` / ``birthtime_readable``: true creation time from
          ``st_birthtime`` (APFS/HFS+).
        - ``ctime_metadata_changed`` / ``ctime_metadata_changed_readable``:
          last inode change (``st_ctime``) — permissions, owner, xattrs.
          *Not* creation time.
        - ``bsd_flags``: a dict of ``immutable``, ``append_only``, ``hidden``
          parsed from the BSD ``st_flags`` bitmask.
    * ``linux``:
        - ``ctime_metadata_changed`` / ``ctime_metadata_changed_readable``:
          same semantics as macOS.
        - ``birthtime`` / ``birthtime_readable``: only present on Python
          3.12+ with a filesystem that records it (ext4, btrfs). ``None``
          otherwise.
    * ``windows``:
        - ``birthtime`` / ``birthtime_readable``: derived from ``st_ctime``,
          which on Windows is the creation time.
        - ``file_attributes``: dict of NTFS attribute booleans (``hidden``,
          ``readonly``, ``system``, ``archive``, ``compressed``, ``encrypted``).
    """
    meta: dict = {}

    if platform == "mac":
        birthtime = getattr(s, "st_birthtime", None)
        meta["birthtime"] = birthtime
        meta["birthtime_readable"] = _ts(birthtime) if birthtime else None
        meta["ctime_metadata_changed"] = s.st_ctime  # type: ignore[attr-defined]
        meta["ctime_metadata_changed_readable"] = _ts(s.st_ctime)  # type: ignore[attr-defined]
        flags = getattr(s, "st_flags", None)
        if flags is not None:
            meta["bsd_flags"] = {
                "immutable": bool(flags & 0x0002),   # UF_IMMUTABLE
                "append_only": bool(flags & 0x0004),  # UF_APPEND
                "hidden": bool(flags & 0x8000),       # UF_HIDDEN (macOS only)
            }

    elif platform == "linux":
        meta["ctime_metadata_changed"] = s.st_ctime  # type: ignore[attr-defined]
        meta["ctime_metadata_changed_readable"] = _ts(s.st_ctime)  # type: ignore[attr-defined]
        # st_birthtime requires Python 3.12+ and a filesystem that records it
        birthtime = getattr(s, "st_birthtime", None)
        meta["birthtime"] = birthtime
        meta["birthtime_readable"] = _ts(birthtime) if birthtime else None

    elif platform == "windows":
        # st_ctime means creation time on Windows, unlike macOS/Linux
        meta["birthtime"] = s.st_ctime  # type: ignore[attr-defined]
        meta["birthtime_readable"] = _ts(s.st_ctime)  # type: ignore[attr-defined]
        file_attrs = getattr(s, "st_file_attributes", None)
        if file_attrs is not None:
            meta["file_attributes"] = {
                "hidden":     bool(file_attrs & stat_mod.FILE_ATTRIBUTE_HIDDEN),
                "readonly":   bool(file_attrs & stat_mod.FILE_ATTRIBUTE_READONLY),
                "system":     bool(file_attrs & stat_mod.FILE_ATTRIBUTE_SYSTEM),
                "archive":    bool(file_attrs & stat_mod.FILE_ATTRIBUTE_ARCHIVE),
                "compressed": bool(file_attrs & stat_mod.FILE_ATTRIBUTE_COMPRESSED),
                "encrypted":  bool(file_attrs & stat_mod.FILE_ATTRIBUTE_ENCRYPTED),
            }

    return meta


def scan_candidate_dir(
    path: Path,
    platform: str,
    progress_callback: Optional[Callable[[int], None]] = None,
) -> dict:
    """Collect metadata for one candidate directory and everything inside it.

    Walks ``path`` recursively via ``Path.rglob("*")``. For every file
    encountered it tracks the newest ``st_mtime`` (and the file that produced
    it), a ``YYYY-MM`` histogram of last-modified months, and a histogram of
    resolved owner names.

    ``FileNotFoundError`` and ``PermissionError`` raised while iterating are
    silently skipped: a single inaccessible file or a file that vanishes
    mid-walk should not abort the surrounding scan.

    Parameters
    ----------
    path : pathlib.Path
        Directory to inspect. Must already be a directory; the caller is
        responsible for filtering non-directories out.
    platform : str
        Canonical platform name from :func:`resolve_platform`, forwarded to
        :func:`owner_name` and :func:`_dir_platform_meta`.
    progress_callback : callable, optional
        Function invoked with the running file count roughly every five
        seconds while walking the subtree. Use it to emit progress output
        during long scans on slow media. ``None`` (default) disables
        progress reporting.

    Returns
    -------
    dict
        Record suitable for embedding directly in the JSON manifest. See
        Notes for the key schema.

    Notes
    -----
    Returned keys:

    * ``path`` (str) — absolute path to ``path``.
    * ``platform`` (str) — the resolved platform name.
    * ``dir_mtime`` (float) / ``dir_mtime_readable`` (str) — the directory's
      own modification time.
    * ``newest_file_mtime`` (float | 0) /
      ``newest_file_mtime_readable`` (str | None) — newest ``st_mtime``
      found in the subtree (``0`` / ``None`` if the directory is empty).
    * ``newest_file`` (str | None) — path that produced
      ``newest_file_mtime``.
    * ``file_count`` (int) — total files visited.
    * ``files_by_month`` (dict[str, int]) — ``YYYY-MM`` → count,
      sorted chronologically.
    * ``files_by_owner`` (dict[str, int]) — owner → count, sorted by
      frequency.

    Platform-specific timestamp and attribute fields produced by
    :func:`_dir_platform_meta` are merged in on top of these.
    """
    file_count = 0
    newest_file_mtime = 0
    newest_file = None
    month_counts: Counter = Counter()
    owner_counts: Counter = Counter()
    last_progress = time.monotonic()
    PROGRESS_INTERVAL_SEC = 5.0

    for item in path.rglob("*"):
        try:
            if item.is_file():
                s = item.stat()
                file_count += 1
                mtime = s.st_mtime

                month_counts[datetime.fromtimestamp(mtime).strftime("%Y-%m")] += 1
                owner_counts[owner_name(item, platform)] += 1

                if mtime > newest_file_mtime:
                    newest_file_mtime = mtime
                    newest_file = str(item)

                if progress_callback is not None:
                    now = time.monotonic()
                    if now - last_progress >= PROGRESS_INTERVAL_SEC:
                        progress_callback(file_count)
                        last_progress = now
        except (FileNotFoundError, PermissionError):
            continue

    dir_stat = path.stat()
    result: dict = {
        "path": str(path),
        "platform": platform,
        "dir_mtime": dir_stat.st_mtime,
        "dir_mtime_readable": _ts(dir_stat.st_mtime),
        "newest_file_mtime": newest_file_mtime,
        "newest_file_mtime_readable": _ts(newest_file_mtime) if newest_file_mtime else None,
        "newest_file": newest_file,
        "file_count": file_count,
        "files_by_month": dict(sorted(month_counts.items())),
        "files_by_owner": dict(owner_counts.most_common()),
    }
    # Merge in platform-specific timestamp and attribute fields
    result.update(_dir_platform_meta(dir_stat, platform))
    return result


def _write_manifest_atomic(report: dict, out_path: Path) -> None:
    """Write ``report`` to ``out_path`` atomically.

    Writes to a sibling ``<name>.tmp`` file first and then calls
    :func:`os.replace`, which is atomic on POSIX and on Windows. A reader
    of ``out_path`` therefore always sees either the previous valid
    manifest or the new one — never a half-written file — and a kill
    mid-write cannot corrupt an existing manifest.

    Parameters
    ----------
    report : dict
        Manifest contents to serialize as JSON.
    out_path : pathlib.Path
        Destination path. The temporary file is created in the same
        directory so the rename stays within one filesystem.
    """
    tmp_path = out_path.with_name(out_path.name + ".tmp")
    tmp_path.write_text(json.dumps(report, indent=2))
    os.replace(tmp_path, out_path)


def scan(root: Path, cutoff_ts: float, out_path: Path, platform: str) -> None:
    """Scan every top-level subdirectory of ``root`` and write a JSON manifest.

    The function pre-counts the top-level directories and emits live progress
    to ``stderr`` as it walks each one, so long scans on slow media are
    observable. It also prints a final summary to ``stdout``. It does not
    delete anything.

    Parameters
    ----------
    root : pathlib.Path
        Directory whose immediate children are the candidate set.
        Non-directory children are ignored.
    cutoff_ts : float
        POSIX timestamp from :func:`parse_date`. Files older than this are
        considered stale.
    out_path : pathlib.Path
        Destination path for the JSON manifest. Overwritten unconditionally
        if it already exists.
    platform : str
        Canonical platform name from :func:`resolve_platform`, recorded in
        the manifest and used to choose metadata fields.

    Returns
    -------
    None
        The full result is written to ``out_path``.

    Notes
    -----
    Eligibility rules:

    * **Non-empty directory** — eligible iff the newest file's ``st_mtime``
      is strictly less than ``cutoff_ts``. A single recently-touched file
      anywhere in the subtree keeps the whole directory.
    * **Empty directory** — falls back to the directory's own ``st_mtime``
      compared to ``cutoff_ts``, since there is no file to inspect.

    Directories that are *not* eligible are still recorded — in
    ``skipped_recent_inside`` — so the manifest doubles as an audit log of
    what was protected and why.

    The top-level JSON object contains: ``root``, ``platform``, ``cutoff``,
    ``eligible_count``, ``eligible_dirs``, ``skipped_recent_inside_count``,
    ``skipped_recent_inside``.
    """
    # Pre-count the candidate set so progress lines can show "[i/total]".
    # iterdir() is cheap (a single readdir()) compared to the per-dir recursion.
    top_level_dirs = sorted(c for c in root.iterdir() if c.is_dir())
    total = len(top_level_dirs)
    print(
        f"Found {total} top-level director{'y' if total == 1 else 'ies'} under {root}.",
        file=sys.stderr,
        flush=True,
    )

    results = []
    skipped_recent_inside = []
    overall_start = time.monotonic()

    def build_report() -> dict:
        """Snapshot of the manifest reflecting state through the last finished dir."""
        return {
            "root": str(root),
            "platform": platform,
            "cutoff": datetime.fromtimestamp(cutoff_ts).strftime("%Y-%m-%d"),
            "eligible_count": len(results),
            "eligible_dirs": results,
            "skipped_recent_inside_count": len(skipped_recent_inside),
            "skipped_recent_inside": skipped_recent_inside,
        }

    for i, child in enumerate(top_level_dirs, start=1):
        prefix = f"[{i}/{total}]"
        print(f"{prefix} scanning {child} ...", file=sys.stderr, flush=True)

        dir_start = time.monotonic()

        # Closure captures the current iteration's prefix and dir_start.
        # scan_candidate_dir invokes this synchronously, so the values stay
        # bound to *this* iteration.
        def progress(n: int) -> None:
            elapsed = time.monotonic() - dir_start
            print(
                f"{prefix}   ... {n:,} files so far ({elapsed:.0f}s)",
                file=sys.stderr,
                flush=True,
            )

        info = scan_candidate_dir(child, platform, progress_callback=progress)
        elapsed = time.monotonic() - dir_start

        if info["file_count"] == 0:
            eligible = info["dir_mtime"] < cutoff_ts
        else:
            # A single recent file anywhere in the subtree makes the whole dir ineligible
            eligible = info["newest_file_mtime"] < cutoff_ts

        if eligible:
            results.append(info)
        else:
            skipped_recent_inside.append(info)

        # Checkpoint the manifest after each top-level dir so a kill mid-scan
        # leaves a valid file covering everything completed so far.
        _write_manifest_atomic(build_report(), out_path)

        verdict = "ELIGIBLE" if eligible else "kept (newer content inside)"
        print(
            f"{prefix} done: {info['file_count']:,} files in {elapsed:.1f}s → {verdict}",
            file=sys.stderr,
            flush=True,
        )

    # Final write covers the empty-root case where the loop never ran.
    # Otherwise this duplicates the last checkpoint, which is harmless.
    _write_manifest_atomic(build_report(), out_path)

    overall_elapsed = time.monotonic() - overall_start
    print(f"Wrote scan report: {out_path}")
    print(f"Eligible directories: {len(results)}")
    print(f"Skipped because contents are newer: {len(skipped_recent_inside)}")
    print(f"Total scan time: {overall_elapsed:.1f}s")


def delete_from_manifest(manifest: Path, confirm: bool) -> None:
    """Recursively delete every directory listed in a scan manifest.

    Only entries under ``eligible_dirs`` are removed; ``skipped_recent_inside``
    is ignored. Each candidate is re-validated immediately before deletion
    so that a path that disappeared, was replaced with a file, or was
    explicitly removed from the manifest in review is silently skipped
    rather than causing an error.

    The ``confirm`` flag is a deliberate safeguard against accidental
    invocation — the function refuses to proceed unless the caller has
    passed ``--confirm`` on the command line.

    Parameters
    ----------
    manifest : pathlib.Path
        Path to the JSON file produced by :func:`scan`.
    confirm : bool
        Must be ``True``. Mapped 1:1 from the CLI ``--confirm`` flag.

    Returns
    -------
    None

    Raises
    ------
    SystemExit
        If ``confirm`` is falsy.
    OSError
        Propagated from :func:`shutil.rmtree` if a directory cannot be
        removed (e.g. permissions, busy file handles).
    """
    if not confirm:
        raise SystemExit("Refusing to delete without --confirm")

    report = json.loads(manifest.read_text())
    dirs = report.get("eligible_dirs", [])

    for entry in dirs:
        path = Path(entry["path"])
        # Re-validate: path must still exist and still be a directory.
        # Protects against a file being created at the same path between
        # the scan and this delete run.
        if path.exists() and path.is_dir():
            print(f"Deleting: {path}")
            shutil.rmtree(path)

    print(f"Deleted {len(dirs)} directories.")


def main() -> None:
    """CLI entry point: parse arguments and dispatch to ``scan`` or ``delete``.

    Returns
    -------
    None
        Exits via ``argparse`` with a non-zero status if the command line is
        malformed; otherwise returns once the chosen subcommand has finished.

    Notes
    -----
    Defines two subcommands:

    * ``scan <root> --cutoff YYYY-MM-DD [--out FILE] [--platform PLATFORM]``
      — see :func:`scan`.
    * ``delete <manifest> --confirm`` — see :func:`delete_from_manifest`.
    """
    parser = argparse.ArgumentParser(
        description="Two-phase directory cleanup: scan to manifest, then delete from manifest."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Find old directories and write a manifest.")
    scan_parser.add_argument("root", help="Root directory to scan (checks immediate subdirs).")
    scan_parser.add_argument("--cutoff", required=True, help="Cutoff date in YYYY-MM-DD format.")
    scan_parser.add_argument("--out", default="cleanup_report.json", help="Output manifest path.")
    scan_parser.add_argument(
        "--platform",
        choices=["auto", "mac", "linux", "windows"],
        default="auto",
        help=(
            "OS platform for metadata collection. "
            "'auto' detects the current OS. "
            "Override when scanning a share written by a different OS."
        ),
    )

    delete_parser = sub.add_parser("delete", help="Delete directories listed in a manifest.")
    delete_parser.add_argument("manifest", help="Path to the JSON manifest from a prior scan.")
    delete_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Required: must be passed explicitly to allow deletion.",
    )

    args = parser.parse_args()

    if args.command == "scan":
        platform = resolve_platform(args.platform)
        scan(Path(args.root), parse_date(args.cutoff), Path(args.out), platform)

    elif args.command == "delete":
        delete_from_manifest(Path(args.manifest), args.confirm)


if __name__ == "__main__":
    main()
