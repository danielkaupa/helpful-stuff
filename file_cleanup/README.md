# cleanup_files_older_than.py

A two-phase, safe directory cleanup tool. It separates **scanning** (what would be deleted) from **deleting** (actually removing), so you can review before committing.

## How it works

1. **Scan** — walks every top-level subdirectory under a root path, compares the newest file's modification time against a cutoff date, and writes a JSON manifest of eligible directories.
2. **Delete** — reads that manifest and removes the listed directories.

**Safety rule:** a directory is only eligible if its *newest contained file* is older than the cutoff — not just the directory's own mtime. Empty directories fall back to their own mtime.

## Usage

### scan

```
python cleanup_files_older_than.py scan <root> --cutoff YYYY-MM-DD [--out FILE] [--platform PLATFORM]
```

| Argument | Description |
|---|---|
| `root` | Root directory whose top-level subdirectories are candidates |
| `--cutoff` | Date threshold (`YYYY-MM-DD`). Dirs whose newest file predates this are eligible |
| `--out` | Output JSON report path (default: `cleanup_report.json`) |
| `--platform` | `auto` (default), `mac`, `linux`, or `windows`. Controls which metadata fields are collected |

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

## Platform differences

The `--platform` flag (default: `auto`) controls which metadata the scan collects.
`auto` detects the current OS automatically.

### macOS

| Field | Source | Notes |
|---|---|---|
| `dir_mtime` / `newest_file_mtime` | `st_mtime` | Last content modification |
| `birthtime` | `st_birthtime` | True creation time (APFS/HFS+) |
| `ctime_metadata_changed` | `st_ctime` | Last inode/permission change — **not** creation time |
| `files_by_owner` | `pwd.getpwuid(st_uid)` | Unix username |
| `bsd_flags` | `st_flags` | `immutable`, `append_only`, `hidden` |

### Linux

| Field | Source | Notes |
|---|---|---|
| `dir_mtime` / `newest_file_mtime` | `st_mtime` | Last content modification |
| `birthtime` | `st_birthtime` | Only on Python 3.12+ with supported filesystems (ext4, btrfs); `null` otherwise |
| `ctime_metadata_changed` | `st_ctime` | Last inode/permission change — **not** creation time |
| `files_by_owner` | `pwd.getpwuid(st_uid)` | Unix username |

### Windows

| Field | Source | Notes |
|---|---|---|
| `dir_mtime` / `newest_file_mtime` | `st_mtime` | Last content modification |
| `birthtime` | `st_ctime` | On Windows `st_ctime` **is** the creation time (unlike Unix) |
| `files_by_owner` | `win32security` | Requires `pip install pywin32`; falls back to `"unknown"` |
| `file_attributes` | `st_file_attributes` | `hidden`, `readonly`, `system`, `archive`, `compressed`, `encrypted` |

> **`st_ctime` means different things per OS.** On macOS/Linux it is the last *metadata change* time (permissions, owner, etc.). On Windows it is the file *creation* time. The script surfaces this correctly per platform.

## JSON report format

```json
{
  "root": "/data/models",
  "platform": "mac",
  "cutoff": "2025-01-01",
  "eligible_count": 1,
  "eligible_dirs": [
    {
      "path": "/data/models/run_42",
      "platform": "mac",
      "dir_mtime": 1704067200.0,
      "dir_mtime_readable": "2024-01-01T00:00:00",
      "newest_file_mtime": 1703980800.0,
      "newest_file_mtime_readable": "2023-12-31T00:00:00",
      "newest_file": "/data/models/run_42/weights.pt",
      "file_count": 14,
      "files_by_month": { "2023-12": 14 },
      "files_by_owner": { "daniel": 14 },
      "birthtime": 1700000000.0,
      "birthtime_readable": "2023-11-14T22:13:20",
      "ctime_metadata_changed": 1703980000.0,
      "ctime_metadata_changed_readable": "2023-12-30T21:46:40",
      "bsd_flags": { "immutable": false, "append_only": false, "hidden": false }
    }
  ],
  "skipped_recent_inside_count": 1,
  "skipped_recent_inside": [ "..." ]
}
```

`skipped_recent_inside` lists every directory that was *not* eligible — either because a file inside it is newer than the cutoff, or, for empty directories, because the directory's own mtime is newer than the cutoff. Useful for auditing what was protected and why.

## Windows dependency

Owner resolution on Windows requires the `pywin32` package:

```
pip install pywin32
```

Without it, `files_by_owner` will show `"unknown"` for all entries. Everything else works without it.
