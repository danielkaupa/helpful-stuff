# cleanup_files_older_than.py

A two-phase, safe directory cleanup tool. It separates **scanning** (what would be deleted) from **deleting** (actually removing), so you can review before committing.

## How it works

1. **Scan** — walks every top-level subdirectory under a root path, compares the newest file's modification time against a cutoff date, and writes a JSON manifest of eligible directories.
2. **Delete** — reads that manifest and removes the listed directories.

**Safety rule:** a directory is only eligible if its *newest contained file* is older than the cutoff — not just the directory's own mtime. Empty directories fall back to their own mtime.

**Name-based protection:** directories whose basename matches the per-platform exclude list at the top of the script (`EXCLUDED_DIR_NAMES_MAC`, `..._LINUX`, `..._WINDOWS`) are never walked and never marked eligible. This covers things like `Documents`, `Downloads`, `$RECYCLE.BIN`, `.Trashes` that should be off-limits regardless of how long ago they were touched. The same names are pruned at any depth, so e.g. a `.Trashes` nested inside an otherwise old project does not protect that project's parent dir. See the [Excluded directory names](#excluded-directory-names) section below for the full default list and how to edit it.

**Crash safety:** `scan` rewrites the manifest atomically (write-to-tmp, then rename) after every top-level directory it finishes. Ctrl-C mid-scan leaves a valid manifest covering exactly the directories that completed, and never corrupts a pre-existing manifest at the output path.

## Usage

### scan

```
python cleanup_files_older_than.py scan <root> --cutoff YYYY-MM-DD [--out FILE] [--platform PLATFORM] [--report-every N[unit]]
```

| Argument | Description |
|---|---|
| `root` | Root directory whose top-level subdirectories are candidates |
| `--cutoff` | Date threshold (`YYYY-MM-DD`). Dirs whose newest file predates this are eligible |
| `--out` | Output JSON report path (default: `cleanup_report.json`) |
| `--platform` | `auto` (default), `mac`, `linux`, or `windows`. Controls which metadata fields are collected |
| `--report-every` | Intra-directory heartbeat cadence. Plain integer = files (default `20000`); suffix `s`/`m`/`h` = wall-clock time. Examples: `100000`, `60s`, `5m`, `1h` |

### delete

```
python cleanup_files_older_than.py delete <manifest> --confirm
```

| Argument | Description |
|---|---|
| `manifest` | Path to the JSON report produced by `scan` |
| `--confirm` | Required flag — refuses to delete without it |

## Examples

```bash
# Step 1: find all directories under /data/models last touched before 2025-01-01
python cleanup_files_older_than.py scan /data/models --cutoff 2025-01-01 --out old_models.json

# Override platform detection (e.g. running on a Mac analysing a Linux-mounted share)
python cleanup_files_older_than.py scan /mnt/share --cutoff 2025-01-01 --platform linux

# Review old_models.json, then delete
python cleanup_files_older_than.py delete old_models.json --confirm
```

## Progress output

`scan` prints progress to **stderr** while it works, so the JSON manifest path printed to stdout stays clean for piping. Sample run on a slow drive:

```
Found 12 top-level directories under /mnt/data.
[1/12] scanning /mnt/data/run_01 ...
[1/12]   ... 20,000 files so far (6s)
[1/12]   ... 40,000 files so far (13s)
[1/12] done: 41,873 files in 13.4s → ELIGIBLE
[2/12] scanning /mnt/data/run_02 ...
[2/12] done: 412 files in 0.4s → kept (newer content inside)
...
Wrote scan report: /mnt/data/old.json
Eligible directories: 7
Skipped because contents are newer: 5
Skipped because name is protected: 0
Total scan time: 142.7s
```

- The intra-dir `... N files so far (Ts)` heartbeat is controlled by `--report-every`. By default it fires every 20,000 files — only for dirs large enough to cross the threshold. Small dirs go straight from `scanning` to `done` with no heartbeat in between.
- The interval can be a file count (`--report-every 100000`) **or** a wall-clock interval (`--report-every 60s`, `5m`, `1h`). Choose whichever matches your drive: file-count mode is steady regardless of drive speed; time mode keeps the log volume predictable on very fast or very slow media.
- The manifest at `--out` is rewritten atomically after each `[i/total] done:` line, so you can `cat` it (or kill the scan) at any time and always get a valid JSON file.
- Redirect only the manifest summary with `2>/dev/null`, or only the progress with `>/dev/null`.

## Excluded directory names

Three frozenset constants at the top of `cleanup_files_older_than.py` define the directories that should never be walked or considered for deletion:

- `EXCLUDED_DIR_NAMES_MAC`
- `EXCLUDED_DIR_NAMES_LINUX`
- `EXCLUDED_DIR_NAMES_WINDOWS`

The active set is chosen by `--platform` (or by `auto`-detection). To see the *current* contents — this README does not duplicate the values, so it can't drift — run the `show-excludes` subcommand:

```bash
# Print all three platforms' lists
python cleanup_files_older_than.py show-excludes

# Print just one platform
python cleanup_files_older_than.py show-excludes --platform mac
python cleanup_files_older_than.py show-excludes --platform linux
python cleanup_files_older_than.py show-excludes --platform windows
```

Sample output (truncated):

```
=== mac (24 names) ===
  .aws
  .config
  ...
  Documents
  Downloads
  ...
```

How the matching works:

- **Case-insensitive.** `documents`, `Documents`, `DOCUMENTS` all match.
- **Applied at every depth.** At the top level, a matching directory is recorded in the manifest under `skipped_protected` and skipped. At any deeper level inside an otherwise-eligible candidate, the subtree is silently pruned — its contents do not count toward the parent's newest-mtime decision.
- **Edit freely.** Add project- or environment-specific names by appending to the appropriate frozenset at the top of `cleanup_files_older_than.py`. Be careful adding things like `node_modules`, `.git`, `.venv`, or `__pycache__` — those subtrees carry real activity signal (a recent `npm install` or `git commit` would otherwise correctly protect their parent project from deletion). After editing, run `show-excludes` to confirm the change.

## Platform differences

The `--platform` flag (default: `auto`) controls which metadata the scan collects.
`auto` detects the current OS automatically.

All timestamps in the manifest are ISO-8601 strings, not POSIX seconds.

### macOS

| Field | Source | Notes |
|---|---|---|
| `dir_last_modified` / `newest_file_last_modified` | `st_mtime` | When the directory's entry list or a file's contents last changed |
| `dir_created` | `st_birthtime` | True creation time (APFS/HFS+) |
| `dir_metadata_last_changed` | `st_ctime` | Last inode/permission change — **not** creation time |
| `files_by_owner` | `pwd.getpwuid(st_uid)` | Unix username |
| `dir_bsd_flags` | `st_flags` | `immutable`, `append_only`, `hidden` |

### Linux

| Field | Source | Notes |
|---|---|---|
| `dir_last_modified` / `newest_file_last_modified` | `st_mtime` | When the directory's entry list or a file's contents last changed |
| `dir_created` | `st_birthtime` | Only on Python 3.12+ with supported filesystems (ext4, btrfs); `null` otherwise |
| `dir_metadata_last_changed` | `st_ctime` | Last inode/permission change — **not** creation time |
| `files_by_owner` | `pwd.getpwuid(st_uid)` | Unix username |

### Windows

| Field | Source | Notes |
|---|---|---|
| `dir_last_modified` / `newest_file_last_modified` | `st_mtime` | When the directory's entry list or a file's contents last changed |
| `dir_created` | `st_ctime` | On Windows `st_ctime` **is** the creation time (unlike Unix) |
| `files_by_owner` | `win32security` | Requires `pip install pywin32`; falls back to `"unknown"` |
| `dir_file_attributes` | `st_file_attributes` | `hidden`, `readonly`, `system`, `archive`, `compressed`, `encrypted` |

> **`st_ctime` means different things per OS.** On macOS/Linux it is the last *metadata change* time (permissions, owner, etc.). On Windows it is the file *creation* time. The script surfaces this correctly per platform — under the names `dir_metadata_last_changed` and `dir_created` respectively.

## JSON report format

```json
{
  "root": "/data/models",
  "platform": "mac",
  "cutoff": "2025-01-01",
  "eligible_count": 1,
  "eligible_dirs": [
    {
      "dir_name": "run_42",
      "path": "/data/models/run_42",
      "dir_last_modified":         "2024-01-01T00:00:00",
      "dir_created":               "2023-11-14T22:13:20",
      "dir_size": "3.4 GB",
      "file_count": 14,
      "files_by_month": { "2023-12": 14 },
      "files_by_owner": { "daniel": 14 },
      "newest_file_name":          "weights.pt",
      "newest_file_path":          "/data/models/run_42/weights.pt",
      "newest_file_last_modified": "2023-12-31T00:00:00",
      "newest_file_created":       "2023-12-15T09:21:07",
      "dir_metadata_last_changed": "2023-12-30T21:46:40",
      "dir_bsd_flags": { "immutable": false, "append_only": false, "hidden": false }
    }
  ],
  "skipped_recent_inside_count": 1,
  "skipped_recent_inside": [ "..." ],
  "skipped_protected_count": 2,
  "skipped_protected": [
    { "path": "/Users/dan/Documents", "name": "Documents" },
    { "path": "/Users/dan/Downloads", "name": "Downloads" }
  ],
  "run_metadata": {
    "scan_started_at": "2026-06-19T18:30:15",
    "last_updated_at": "2026-06-19T18:31:23",
    "elapsed": "1m 8s",
    "root_scanned": "/data/models",
    "cutoff_date": "2025-01-01",
    "platform": "mac",
    "report_every": "every 20,000 files",
    "cli_invocation": "cleanup_files_older_than.py scan /data/models --cutoff 2025-01-01 --out old_models.json",
    "python_version": "3.11.13",
    "hostname": "macbook-pro.local"
  }
}
```

`skipped_recent_inside` lists every directory that was scanned but *not* eligible — either because a file inside it is newer than the cutoff, or, for empty directories, because the directory's own mtime is newer than the cutoff.

`skipped_protected` lists every top-level directory that was skipped *without scanning*, because its basename matched the per-platform exclude list. Use this to audit which off-limits names appeared under your root.

`run_metadata` makes every manifest self-describing: when the scan started, when it was last updated (rewritten on each checkpoint, so it doubles as a liveness signal mid-run), how long it took, the exact CLI invocation, and the host/Python version that produced it. Useful when you find a manifest in a backup six months from now and need to know what produced it.

## Windows dependency

Owner resolution on Windows requires the `pywin32` package:

```
pip install pywin32
```

Without it, `files_by_owner` will show `"unknown"` for all entries. Everything else works without it.
