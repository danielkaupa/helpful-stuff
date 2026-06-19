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
* Directories whose basename matches the per-platform exclude list
  (see ``EXCLUDED_DIR_NAMES_MAC`` / ``..._LINUX`` / ``..._WINDOWS`` at
  the top of this module) are never walked or marked eligible — useful
  for ``Documents``, ``Downloads``, ``$RECYCLE.BIN``, ``.Trashes`` and
  similar names that should always be off-limits regardless of age.
  The same names are pruned at any depth during recursion, so they
  also do not contribute mtime signal to any parent's eligibility.
* ``delete`` re-checks that each path still exists and is still a
  directory, so the manifest going stale between phases is harmless.
* ``delete`` refuses to run without ``--confirm``.
* ``scan`` rewrites the manifest atomically (write-then-rename) after
  every top-level directory it finishes, so a Ctrl-C mid-scan leaves a
  valid manifest covering exactly the directories that completed —
  and never corrupts an existing manifest at the output path.

Observability:

* ``scan`` pre-counts the top-level directories and emits
  ``[i/total] scanning …`` / ``[i/total] done: N files in Ts → …``
  progress lines to stderr, with an intra-directory
  ``… N files so far (Ts)`` heartbeat whose cadence is controlled by
  ``--report-every`` (e.g. ``100000``, ``60s``, ``5m``, ``1h``;
  default ``20000`` files). The JSON manifest is written to ``--out``
  and the final summary to stdout, so progress can be redirected
  independently.
* Every manifest carries a ``run_metadata`` block at the end recording
  the start/last-updated wall-clock times, elapsed duration, the exact
  CLI used, Python version, and hostname. Because the block is
  regenerated on each checkpoint, ``last_updated_at`` doubles as a
  liveness signal when you inspect the manifest mid-run.

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

Print the currently configured exclude lists (so the README never goes stale)::

    python cleanup_files_older_than.py show-excludes --platform mac
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import socket
import stat as stat_mod
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Callable, FrozenSet, Iterator, Optional, Tuple


# ---------------------------------------------------------------------------
# Per-platform exclude lists
#
# A directory whose basename appears here is *never* walked into and *never*
# marked eligible for deletion, no matter how old it is. The check fires both
# at the top level of the scanned root AND at any depth during recursion, so
# e.g. ``$RECYCLE.BIN`` nested inside a candidate dir is also pruned.
#
# Matching is case-insensitive (basename is lowercased and compared against
# the lowercased contents of the set), so the natural-case entries below work
# on case-sensitive Linux filesystems and case-insensitive macOS/Windows
# filesystems alike.
#
# Edit these sets to fit your environment — they're declared as constants
# here precisely so you don't have to dig through the implementation.
# ---------------------------------------------------------------------------

EXCLUDED_DIR_NAMES_MAC: FrozenSet[str] = frozenset({
    # Standard user folders under ~ — never delete these
    "Documents", "Downloads", "Desktop", "Pictures", "Music", "Movies", "Public",
    # macOS user library, system apps
    "Library", "Applications",
    # Common config / state dirs
    ".ssh", ".config", ".gnupg", ".aws", ".docker", ".kube",
    # Cloud sync roots
    "iCloud Drive", "OneDrive", "Dropbox", "Google Drive",
    # macOS system metadata / trash — should never be walked
    ".Trashes", ".Spotlight-V100", ".fseventsd",
    ".TemporaryItems", ".DocumentRevisions-V100",
})

EXCLUDED_DIR_NAMES_LINUX: FrozenSet[str] = frozenset({
    # XDG user folders
    "Documents", "Downloads", "Desktop", "Pictures", "Music", "Videos",
    "Templates", "Public",
    # Common config / state dirs
    ".ssh", ".config", ".gnupg", ".aws", ".docker", ".kube", ".local",
    # Trash + filesystem recovery
    ".Trash", "lost+found",
})

EXCLUDED_DIR_NAMES_WINDOWS: FrozenSet[str] = frozenset({
    # Standard user folders
    "Documents", "Downloads", "Desktop", "Pictures", "Music", "Videos",
    "Favorites", "Contacts", "Saved Games", "Searches", "Links", "3D Objects",
    # Application data + roaming profile bits
    "AppData", "Application Data", "Local Settings",
    # Cloud sync roots
    "OneDrive", "Dropbox", "Google Drive",
    # Trash + system metadata (one per volume on Windows)
    "$RECYCLE.BIN", "RECYCLER", "System Volume Information",
    # System/installation roots — only relevant if scanning C:\
    "Program Files", "Program Files (x86)", "ProgramData", "Windows",
})


def print_excludes(which: str) -> None:
    """Print the configured exclude lists to stdout.

    This is the canonical "what is currently protected?" view for human
    consumption, used by the CLI ``show-excludes`` subcommand. Because the
    lists live in Python constants, the README does *not* duplicate them —
    callers run this command to see the live values.

    Parameters
    ----------
    which : str
        ``"all"`` to print every platform's list (each in its own section),
        or ``"mac"`` / ``"linux"`` / ``"windows"`` to print just that one.

    Returns
    -------
    None
        Output goes directly to ``stdout``.
    """
    sets = {
        "mac": EXCLUDED_DIR_NAMES_MAC,
        "linux": EXCLUDED_DIR_NAMES_LINUX,
        "windows": EXCLUDED_DIR_NAMES_WINDOWS,
    }
    targets = sets.items() if which == "all" else [(which, sets[which])]
    for i, (name, entries) in enumerate(targets):
        if i > 0:
            print()
        print(f"=== {name} ({len(entries)} names) ===")
        for entry in sorted(entries, key=str.lower):
            print(f"  {entry}")


def _excluded_lower_for(platform: str) -> FrozenSet[str]:
    """Return the lowercased exclude set for ``platform``.

    Parameters
    ----------
    platform : str
        Canonical platform name from :func:`resolve_platform`.

    Returns
    -------
    frozenset of str
        Lowercased basenames to skip. An unrecognized platform yields an
        empty set (no exclusions).
    """
    by_platform = {
        "mac": EXCLUDED_DIR_NAMES_MAC,
        "linux": EXCLUDED_DIR_NAMES_LINUX,
        "windows": EXCLUDED_DIR_NAMES_WINDOWS,
    }
    return frozenset(name.lower() for name in by_platform.get(platform, frozenset()))


def _iter_files(root: str, excluded_lower: FrozenSet[str]) -> Iterator["os.DirEntry[str]"]:
    """Yield ``DirEntry`` for every file under ``root``, pruning excluded subtrees.

    The walk is iterative (a stack, not Python recursion) so it cannot blow
    the recursion limit on deep trees. Symlinks are not followed, to avoid
    infinite loops on cyclic mounts. Any directory whose lowercased basename
    is in ``excluded_lower`` is silently skipped — its contents do not
    contribute to file counts or mtime decisions.

    Parameters
    ----------
    root : str
        Directory to walk recursively. Must exist and be a directory.
    excluded_lower : frozenset of str
        Lowercased basenames to prune from the walk.

    Yields
    ------
    os.DirEntry
        One entry per regular file. ``FileNotFoundError``,
        ``PermissionError``, and other ``OSError`` raised while scanning are
        swallowed silently.
    """
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name.lower() in excluded_lower:
                                continue
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            yield entry
                    except OSError:
                        continue
        except OSError:
            continue


def _parse_report_interval(s: str) -> Tuple[str, float]:
    """Parse the ``--report-every`` CLI value into a mode and magnitude.

    Accepts a positive integer with an optional unit suffix:

    * no suffix or ``f`` — files (e.g. ``20000``, ``100000f``)
    * ``s`` — seconds (e.g. ``60s``, ``120s``)
    * ``m`` — minutes (e.g. ``5m``, ``60m``); converted to seconds
    * ``h`` — hours (e.g. ``1h``, ``2h``); converted to seconds

    Matching is case-insensitive and whitespace-tolerant. ``0`` and
    negative values are rejected because the file-count mode uses
    ``file_count % value`` (which would div-by-zero on 0).

    Parameters
    ----------
    s : str
        The raw flag value as supplied by the user.

    Returns
    -------
    tuple of (str, float)
        ``("files", n)`` to fire every ``n`` files, or
        ``("seconds", n)`` to fire every ``n`` seconds of wall-clock
        time.

    Raises
    ------
    argparse.ArgumentTypeError
        If ``s`` does not match the grammar above, or if the numeric
        component is not strictly positive.
    """
    raw = s.strip().lower()
    m = re.fullmatch(r"(\d+)\s*([smhf]?)", raw)
    if not m:
        raise argparse.ArgumentTypeError(
            f"Invalid --report-every value {s!r}. "
            "Use a positive integer with optional unit suffix: "
            "f=files (default), s=seconds, m=minutes, h=hours. "
            "Examples: 100000, 100000f, 60s, 5m, 1h."
        )
    n = int(m.group(1))
    if n <= 0:
        raise argparse.ArgumentTypeError(
            f"--report-every must be a positive integer (got {n})."
        )
    unit = m.group(2) or "f"
    if unit == "f":
        return ("files", float(n))
    if unit == "s":
        return ("seconds", float(n))
    if unit == "m":
        return ("seconds", float(n * 60))
    if unit == "h":
        return ("seconds", float(n * 3600))
    # Unreachable because the regex restricts the unit set, but appease type checkers.
    raise argparse.ArgumentTypeError(f"Unknown unit {unit!r} in {s!r}.")


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


def _human_size(n: float) -> str:
    """Format a byte count as a short human-readable string.

    Uses binary (1024-based) prefixes because filesystem sizes are
    traditionally reported that way. Two-decimal precision is plenty for
    review purposes — humans look at this to gauge "is this big?".

    Parameters
    ----------
    n : float
        Byte count. Negative values are passed through unchanged so
        unusual inputs don't silently disappear.

    Returns
    -------
    str
        Examples: ``"0 B"``, ``"512 B"``, ``"1.5 KB"``, ``"2.3 MB"``,
        ``"1.1 GB"``, ``"4.7 TB"``.
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _human_duration(seconds: float) -> str:
    """Format an elapsed duration as a short human-readable string.

    Examples
    --------
    >>> _human_duration(4.2)
    '4.2s'
    >>> _human_duration(83)
    '1m 23s'
    >>> _human_duration(3725)
    '1h 2m 5s'
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {int(secs)}s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes)}m {int(secs)}s"


def _describe_report_every(
    report_every_files: Optional[int],
    report_every_seconds: Optional[float],
) -> str:
    """Describe the configured heartbeat cadence in plain English."""
    if report_every_files is not None:
        return f"every {report_every_files:,} files"
    if report_every_seconds is not None:
        return f"every {_human_duration(report_every_seconds)} wall-clock"
    return "disabled"


def _creation_time_iso(s: os.stat_result, platform: str) -> Optional[str]:
    """Return the ISO-8601 creation time for a stat result, or ``None``.

    Used for both directory and file creation times — the per-platform
    mapping is identical:

    * macOS: ``st_birthtime`` (APFS/HFS+).
    * Linux: ``st_birthtime`` if Python 3.12+ and the filesystem records
      it; ``None`` otherwise.
    * Windows: ``st_ctime`` (on NTFS this *is* the creation time, the
      opposite convention to Unix).

    Parameters
    ----------
    s : os.stat_result
        Stat result for any file or directory.
    platform : str
        Canonical platform name from :func:`resolve_platform`.

    Returns
    -------
    str or None
        ISO-8601 string in local time, or ``None`` if the platform/FS
        does not expose a creation time.
    """
    if platform == "windows":
        return _ts(s.st_ctime)  # type: ignore[attr-defined]
    birthtime = getattr(s, "st_birthtime", None)
    return _ts(birthtime) if birthtime else None


def _ts(ts: float) -> str:
    """Format a POSIX timestamp as a local-time ISO-8601 string.

    Every timestamp in the manifest (``dir_last_modified``,
    ``newest_file_last_modified``, ``dir_created``, etc.) passes through
    this function so the schema stays consistently ISO-only — raw POSIX
    seconds never appear in the output.

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
    All timestamp fields are ISO-8601 strings. Raw POSIX seconds are not
    exposed because the manifest is intended for human review. The
    ``dir_created`` field is produced separately by
    :func:`_creation_time_iso` and placed earlier in the entry by
    :func:`scan_candidate_dir`; this function returns only the trailing
    platform-specific extras.

    Per-platform fields:

    * ``mac``:
        - ``dir_metadata_last_changed`` (str): last inode change
          (``st_ctime``) — permissions, owner, xattrs. *Not* creation time.
        - ``dir_bsd_flags`` (dict): ``immutable`` / ``append_only`` /
          ``hidden`` parsed from the BSD ``st_flags`` bitmask. See the
          README for what BSD flags are.
    * ``linux``:
        - ``dir_metadata_last_changed`` (str): same semantics as macOS.
    * ``windows``:
        - ``dir_file_attributes`` (dict): NTFS attribute booleans
          (``hidden``, ``readonly``, ``system``, ``archive``,
          ``compressed``, ``encrypted``).
    """
    meta: dict = {}

    if platform == "mac":
        meta["dir_metadata_last_changed"] = _ts(s.st_ctime)  # type: ignore[attr-defined]
        flags = getattr(s, "st_flags", None)
        if flags is not None:
            meta["dir_bsd_flags"] = {
                "immutable": bool(flags & 0x0002),   # UF_IMMUTABLE
                "append_only": bool(flags & 0x0004),  # UF_APPEND
                "hidden": bool(flags & 0x8000),       # UF_HIDDEN (macOS only)
            }

    elif platform == "linux":
        meta["dir_metadata_last_changed"] = _ts(s.st_ctime)  # type: ignore[attr-defined]

    elif platform == "windows":
        file_attrs = getattr(s, "st_file_attributes", None)
        if file_attrs is not None:
            meta["dir_file_attributes"] = {
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
    excluded_lower: Optional[FrozenSet[str]] = None,
    report_every_files: Optional[int] = None,
    report_every_seconds: Optional[float] = None,
) -> Tuple[dict, float]:
    """Collect metadata for one candidate directory and everything inside it.

    Walks ``path`` recursively via :func:`_iter_files`. Subdirectories whose
    basenames are in ``excluded_lower`` are pruned at every depth, so e.g.
    a nested ``.Trashes`` is never descended into and contributes nothing to
    the file count or newest-mtime decision. For every file actually visited
    the function tracks the newest ``st_mtime`` (and the file that produced
    it), a ``YYYY-MM`` histogram of last-modified months, and a histogram of
    resolved owner names.

    ``FileNotFoundError``, ``PermissionError``, and other ``OSError`` raised
    while iterating are silently skipped: a single inaccessible file or a
    file that vanishes mid-walk should not abort the surrounding scan.

    Parameters
    ----------
    path : pathlib.Path
        Directory to inspect. Must already be a directory; the caller is
        responsible for filtering non-directories out.
    platform : str
        Canonical platform name from :func:`resolve_platform`, forwarded to
        :func:`owner_name` and :func:`_dir_platform_meta`.
    progress_callback : callable, optional
        Function invoked with the running file count whenever the
        heartbeat trigger fires (see ``report_every_files`` /
        ``report_every_seconds``). Use it to emit progress output on
        long scans without flooding stderr. ``None`` (default) disables
        progress reporting regardless of the trigger settings.
    excluded_lower : frozenset of str, optional
        Lowercased directory basenames to prune from the recursive walk.
        Defaults to the platform-appropriate set (see
        :func:`_excluded_lower_for`). Pass an empty frozenset to disable
        pruning entirely.
    report_every_files : int, optional
        File-count heartbeat threshold. Fires the callback whenever
        ``file_count`` becomes a positive multiple of this value. Mutually
        exclusive with ``report_every_seconds``; pass exactly one. ``None``
        and ``report_every_seconds=None`` together suppress the heartbeat.
    report_every_seconds : float, optional
        Wall-clock heartbeat interval in seconds. Fires the callback at
        most once per this many seconds while the walk is in progress.
        Mutually exclusive with ``report_every_files``.

    Returns
    -------
    info : dict
        Record suitable for embedding directly in the JSON manifest. See
        Notes for the key schema. All timestamps are ISO-8601 strings; the
        raw POSIX seconds used internally are not exposed.
    eligibility_mtime : float
        Raw POSIX seconds the caller should compare against the cutoff to
        decide whether the directory is eligible. Equals the newest file's
        ``st_mtime`` if any files were visited, otherwise the directory's
        own ``st_mtime`` (the empty-directory fallback).

    Notes
    -----
    Returned ``info`` keys, in insertion (and therefore serialized) order:

    1. ``dir_name`` (str) — basename of ``path``.
    2. ``path`` (str) — absolute directory path.
    3. ``dir_last_modified`` (str) — ISO time the directory's entry list
       was last changed (a child added or removed).
    4. ``dir_created`` (str | None) — ISO creation time of the directory.
       ``None`` on Linux without ``st_birthtime``.
    5. ``dir_size`` (str) — total size of all visited files, human-formatted
       (e.g. ``"1.2 GB"``). Excludes pruned subtrees.
    6. ``file_count`` (int) — total files visited (excludes pruned subtrees).
    7. ``files_by_month`` (dict[str, int]) — ``YYYY-MM`` → count, sorted
       chronologically.
    8. ``files_by_owner`` (dict[str, int]) — owner → count, sorted by
       frequency.
    9. ``newest_file_name`` (str | None) — basename of the file with the
       newest ``st_mtime`` in the subtree.
    10. ``newest_file_path`` (str | None) — absolute path of that file.
    11. ``newest_file_last_modified`` (str | None) — ISO ``st_mtime`` of
        that file.
    12. ``newest_file_created`` (str | None) — ISO creation time of that
        file.

    After the primary fields, :func:`_dir_platform_meta` appends the
    trailing platform-specific extras (``dir_metadata_last_changed`` plus
    ``dir_bsd_flags`` or ``dir_file_attributes``). The platform itself is
    not repeated per entry — it appears once at the top of the report
    written by :func:`scan`.
    """
    if excluded_lower is None:
        excluded_lower = _excluded_lower_for(platform)

    file_count = 0
    total_size = 0
    newest_file_mtime = 0
    newest_file = None
    newest_file_created_iso: Optional[str] = None
    month_counts: Counter = Counter()
    owner_counts: Counter = Counter()
    # Used only for the seconds-based heartbeat; cheap to maintain either way.
    last_heartbeat_time = time.monotonic()

    for entry in _iter_files(str(path), excluded_lower):
        try:
            s = entry.stat()
            file_count += 1
            total_size += s.st_size
            mtime = s.st_mtime

            month_counts[datetime.fromtimestamp(mtime).strftime("%Y-%m")] += 1
            owner_counts[owner_name(Path(entry.path), platform)] += 1

            if mtime > newest_file_mtime:
                newest_file_mtime = mtime
                newest_file = entry.path
                newest_file_created_iso = _creation_time_iso(s, platform)

            # Heartbeat trigger. The per-folder "begin" / "done" lines come
            # from scan(); this only fires for very large dirs that cross
            # whichever threshold is configured.
            if progress_callback is not None:
                fire = False
                if (
                    report_every_files is not None
                    and file_count % report_every_files == 0
                ):
                    fire = True
                elif report_every_seconds is not None:
                    now = time.monotonic()
                    if now - last_heartbeat_time >= report_every_seconds:
                        last_heartbeat_time = now
                        fire = True
                if fire:
                    progress_callback(file_count)
        except (FileNotFoundError, PermissionError):
            continue

    dir_stat = path.stat()

    # Build the entry in the order a human review reads it: identify the
    # directory, describe its own timestamps and size, then drill down to
    # the contents and finally to the single newest file.
    result: dict = {
        "dir_name": path.name,
        "path": str(path),
        "dir_last_modified": _ts(dir_stat.st_mtime),
        "dir_created": _creation_time_iso(dir_stat, platform),
        "dir_size": _human_size(total_size),
        "file_count": file_count,
        "files_by_month": dict(sorted(month_counts.items())),
        "files_by_owner": dict(owner_counts.most_common()),
        "newest_file_name": Path(newest_file).name if newest_file else None,
        "newest_file_path": newest_file,
        "newest_file_last_modified": _ts(newest_file_mtime) if newest_file_mtime else None,
        "newest_file_created": newest_file_created_iso,
    }
    # Trailing extras: platform-specific metadata. The platform itself is
    # not duplicated per entry — it appears once at the top of the report.
    result.update(_dir_platform_meta(dir_stat, platform))

    # eligibility_mtime is the raw POSIX timestamp the caller should compare
    # against the cutoff. Returned separately so the manifest itself stays
    # ISO-only — humans never see raw seconds, but scan() still has the value
    # it needs to make the eligibility decision without re-parsing strings.
    eligibility_mtime = newest_file_mtime if file_count > 0 else dir_stat.st_mtime
    return result, eligibility_mtime


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


def scan(
    root: Path,
    cutoff_ts: float,
    out_path: Path,
    platform: str,
    report_every_files: Optional[int] = None,
    report_every_seconds: Optional[float] = None,
) -> None:
    """Scan every top-level subdirectory of ``root`` and write a JSON manifest.

    The function pre-counts the top-level directories and emits live progress
    to ``stderr`` as it walks each one, so long scans on slow media are
    observable. After each top-level directory completes, the manifest is
    re-serialized to ``out_path`` atomically (via
    :func:`_write_manifest_atomic`), so a kill mid-scan leaves a valid
    partial manifest covering every directory that finished. The final
    summary (including total elapsed time) is printed to ``stdout``. It
    does not delete anything.

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

    Top-level children whose basename matches the per-platform exclude list
    (see :data:`EXCLUDED_DIR_NAMES_MAC` / ``..._LINUX`` / ``..._WINDOWS`` at
    the top of this module) are *never* walked or considered for deletion.
    They are recorded in ``skipped_protected`` for audit and the loop moves
    on. The same names are also pruned at any depth during recursion via
    :func:`scan_candidate_dir`, so e.g. a nested ``$RECYCLE.BIN`` is
    silently ignored.

    Directories that scan but turn out to have recent content are recorded
    in ``skipped_recent_inside`` instead, so the manifest doubles as an
    audit log of what was protected and why.

    The top-level JSON object contains: ``root``, ``platform``, ``cutoff``,
    ``eligible_count``, ``eligible_dirs``, ``skipped_recent_inside_count``,
    ``skipped_recent_inside``, ``skipped_protected_count``,
    ``skipped_protected``, and a trailing ``run_metadata`` block
    (start/last-updated times, elapsed, CLI invocation, Python version,
    hostname).
    """
    excluded_lower = _excluded_lower_for(platform)

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
    skipped_protected = []
    overall_start = time.monotonic()
    started_at = datetime.now()

    def build_report() -> dict:
        """Snapshot of the manifest reflecting state through the last finished dir.

        Includes a ``run_metadata`` block at the end describing this
        invocation: wall-clock start time, last update time, elapsed,
        the exact CLI used, Python version, hostname, etc. Because the
        block is regenerated on every checkpoint, ``last_updated_at`` is
        also a useful "this scan is still alive" signal if you inspect
        the manifest mid-run.
        """
        return {
            "root": str(root),
            "platform": platform,
            "cutoff": datetime.fromtimestamp(cutoff_ts).strftime("%Y-%m-%d"),
            "eligible_count": len(results),
            "eligible_dirs": results,
            "skipped_recent_inside_count": len(skipped_recent_inside),
            "skipped_recent_inside": skipped_recent_inside,
            "skipped_protected_count": len(skipped_protected),
            "skipped_protected": skipped_protected,
            "run_metadata": {
                "scan_started_at": started_at.isoformat(timespec="seconds"),
                "last_updated_at": datetime.now().isoformat(timespec="seconds"),
                "elapsed": _human_duration(time.monotonic() - overall_start),
                "root_scanned": str(root),
                "cutoff_date": datetime.fromtimestamp(cutoff_ts).strftime("%Y-%m-%d"),
                "platform": platform,
                "report_every": _describe_report_every(
                    report_every_files, report_every_seconds
                ),
                "cli_invocation": shlex.join(sys.argv),
                "python_version": sys.version.split()[0],
                "hostname": socket.gethostname(),
            },
        }

    for i, child in enumerate(top_level_dirs, start=1):
        prefix = f"[{i}/{total}]"

        # Name-based protection: skip the recursive walk entirely and never
        # mark this directory eligible for deletion.
        if child.name.lower() in excluded_lower:
            skipped_protected.append({"path": str(child), "name": child.name})
            _write_manifest_atomic(build_report(), out_path)
            print(
                f"{prefix} {child} — protected name, skipped",
                file=sys.stderr,
                flush=True,
            )
            continue

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

        info, eligibility_mtime = scan_candidate_dir(
            child,
            platform,
            progress_callback=progress,
            excluded_lower=excluded_lower,
            report_every_files=report_every_files,
            report_every_seconds=report_every_seconds,
        )
        elapsed = time.monotonic() - dir_start

        # eligibility_mtime is the newest file's st_mtime if any files were
        # visited, otherwise the directory's own st_mtime (empty-dir fallback).
        # A single recent file anywhere in the subtree makes the whole dir ineligible.
        eligible = eligibility_mtime < cutoff_ts

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
    print(f"Skipped because name is protected: {len(skipped_protected)}")
    print(f"Total scan time: {overall_elapsed:.1f}s")


def delete_from_manifest(manifest: Path, confirm: bool) -> None:
    """Recursively delete every directory listed in a scan manifest.

    Only entries under ``eligible_dirs`` are removed; ``skipped_recent_inside``
    and ``skipped_protected`` are ignored entirely. Each candidate is
    re-validated immediately before deletion so that a path that
    disappeared, was replaced with a file, or was explicitly removed from
    the manifest during manual review is silently skipped rather than
    causing an error.

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
    Defines three subcommands:

    * ``scan <root> --cutoff YYYY-MM-DD [--out FILE] [--platform PLATFORM]
      [--report-every N[unit]]`` — see :func:`scan`.
    * ``delete <manifest> --confirm`` — see :func:`delete_from_manifest`.
    * ``show-excludes [--platform PLATFORM]`` — see :func:`print_excludes`.
      Prints the currently configured exclude lists so documentation does
      not need to be kept in sync with the constants.
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
    scan_parser.add_argument(
        "--report-every",
        type=_parse_report_interval,
        default=("files", 20_000.0),
        metavar="N[unit]",
        help=(
            "Intra-directory heartbeat interval. Plain integer = files "
            "(e.g. 100000); suffix s/m/h = time (e.g. 60s, 5m, 1h). "
            "Default: 20000 (files)."
        ),
    )

    delete_parser = sub.add_parser("delete", help="Delete directories listed in a manifest.")
    delete_parser.add_argument("manifest", help="Path to the JSON manifest from a prior scan.")
    delete_parser.add_argument(
        "--confirm",
        action="store_true",
        help="Required: must be passed explicitly to allow deletion.",
    )

    show_parser = sub.add_parser(
        "show-excludes",
        help="Print the per-platform protected-name lists.",
    )
    show_parser.add_argument(
        "--platform",
        choices=["all", "mac", "linux", "windows"],
        default="all",
        help="Which platform's list to print. Default: all three.",
    )

    args = parser.parse_args()

    if args.command == "scan":
        platform = resolve_platform(args.platform)
        interval_kind, interval_value = args.report_every
        scan(
            Path(args.root),
            parse_date(args.cutoff),
            Path(args.out),
            platform,
            report_every_files=int(interval_value) if interval_kind == "files" else None,
            report_every_seconds=interval_value if interval_kind == "seconds" else None,
        )

    elif args.command == "delete":
        delete_from_manifest(Path(args.manifest), args.confirm)

    elif args.command == "show-excludes":
        print_excludes(args.platform)


if __name__ == "__main__":
    main()
