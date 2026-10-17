# audit-storage 🔍💾

[![CI Verification](https://github.com/hermes-pantheon-pb/audit-storage/actions/workflows/ci.yml/badge.svg)](https://github.com/hermes-pantheon-pb/audit-storage/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-Standard_Library_Only-orange.svg)]()

> High-performance, read-only Linux storage pool and MergerFS hardlink invariant auditor. Detects desynced tracker databases, silent cross-branch copy fallbacks (`EXDEV`), leftover residue directories, and gapped media / dataset sequences.

---

## ⚡ The Problem: MergerFS, Hardlinks, and Silent Copies

In Linux storage pools combining multiple underlying branch disks (e.g. `/mnt/disk1`, `/mnt/disk2`) via **MergerFS**, applications (Sonarr, Radarr, torrent clients, seedboxes, ML data pipelines) often attempt to hardlink downloaded files into organized library directories.

However:
1. **Cross-Device EXDEV Errors**: POSIX hardlinks cannot cross underlying filesystem boundaries (`st_dev`). If path creation policies place the organized file on a different branch disk than the staging download, the kernel `link()` syscall fails with `EXDEV`.
2. **Silent Copy Fallbacks**: Most import tools silently fall back to `cp` / `shutil.copy()`. This creates **"Ghost Links"**: duplicated files with `st_nlink == 1` consuming double disk space.
3. **Ghost Directories (Residue Only)**: When files or torrents are deleted or upgraded, metadata, subtitles (`.srt`, `.nfo`), and artwork remain behind without any primary payload.
4. **Structural & Gapped Sequences**: Incomplete TV seasons, missing music tracks, or asymmetric ML dataset splits (`train/` without `val/`, `images/` without `labels/`) can persist unnoticed.

`audit-storage` is a **strictly read-only**, streaming diagnostic engine written in pure Python 3.10+ standard library. It never moves, modifies, or deletes any file.

---

## ✨ Features

- **POSIX Inode & Hardlink Invariant Engine**:
  - Maps `(st_dev, st_ino)` across staging/download and library trees.
  - Flags **Orphan Staging Files** (`st_nlink == 1` in downloads with no library link).
  - Verifies **Active Normal Hardlinks** (`st_nlink == 2`).
  - Identifies **Over-Linked Files** (`st_nlink > 2` cross-seeded or duplicate links).
  - Detects **Ghost Links**: Library items that have `st_nlink == 1` while matching an identical filename and byte size in downloads (indicating a copy occurred instead of a hardlink).
- **MergerFS Safety & Device Checking**:
  - Inspects `st_dev` across all target paths.
  - Warns if paths reside on disparate filesystem devices, explaining why hardlinks cannot bridge them and preventing false diagnostic assumptions.
- **Residue / Ghost Directory Detection**:
  - Employs a bottom-up subtree aggregation pass to find directories containing only metadata (`.nfo`, `.srt`, `.txt`, `.sfv`, posters) and zero payloads (>100MB or primary media/archive files).
  - Reports only the top-level ghost folder, completely eliminating nested child duplicates.
- **Gapped Media & Incomplete Datasets**:
  - **TV Series**: Parses `SxxEyy`, `Season X Episode Y`, and `1x02` patterns to find sequence gaps (e.g., E01, E02, E04) and flags single-file orphan seasons.
  - **Music Albums**: Analyzes audio track numbering (`01 - Title.flac`, `1-02 Title.mp3`) to identify missing intermediate track numbers.
  - **Computer Vision & ML Datasets**: Verifies split parity (`images/` vs `labels/`, `train/` vs `val/` or `test/`, and missing manifests like `dataset.json`, `data.yaml`, or `classes.txt`).
- **Memory-Efficient Streaming Traversal**:
  - Built on `os.scandir()` with an iterative post-order traversal to minimize memory overhead even on arrays with millions of files.
- **Categorized Terminal Report & JSON Export**:
  - High-visibility terminal output with ANSI colors (auto-disabled if not a TTY or if `NO_COLOR` is present).
  - Comprehensive structured JSON export for reporting or automation pipelines.

---

## 🚀 Installation

`audit-storage` requires **Python 3.10+** and uses **only standard library modules** (`os`, `sys`, `pathlib`, `re`, `collections`, `argparse`, `json`, `dataclasses`).

### Direct Execution (Standalone)
```bash
git clone https://github.com/hermes-pantheon-pb/audit-storage.git
cd audit-storage
chmod +x audit_storage.py
./audit_storage.py --help
```

### Or Install via Pip
```bash
pip install .
audit-storage --help
```

---

## 📖 Usage & CLI Reference

```text
usage: audit-storage [-h] -d DOWNLOADS -l LIBRARIES [LIBRARIES ...]
                     [-o OUTPUT_JSON] [-v]
                     [--payload-threshold-mb PAYLOAD_THRESHOLD_MB]
                     [--no-color]
```

### Options

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `-d`, `--downloads` | `<path>` | Path to download/staging tree (e.g., torrent / usenet completed folder). |
| `-l`, `--libraries` | `<path> ...` | One or more paths to organized media / dataset library directories. |
| `-o`, `--output-json` | `<file.json>` | Path to write the structured JSON audit report. |
| `-v`, `--verbose` | `flag` | Show detailed item-by-item breakdown instead of truncated sample listings. |
| `--payload-threshold-mb` | `<int>` | Size threshold in MB for primary payload classification in ghost directories (default: `100`). |
| `--no-color` | `flag` | Disable ANSI terminal color codes (also honors `NO_COLOR` environment variable). |

---

## 💡 Examples

### 1. Typical Storage Pool Audit
```bash
./audit_storage.py \
  --downloads /mnt/pool/downloads \
  --libraries /mnt/pool/media/tv /mnt/pool/media/movies /mnt/pool/media/music
```

### 2. Comprehensive Verbose Audit with JSON Report Export
```bash
./audit_storage.py \
  --downloads /mnt/pool/downloads \
  --libraries /mnt/pool/media/tv /mnt/pool/media/movies /mnt/pool/datasets \
  --verbose \
  --output-json /mnt/pool/reports/storage_audit_$(date +%F).json
```

---

## 🖥 Sample Terminal Output

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 STORAGE POOL & HARDLINK INVARIANT AUDIT REPORT v1.0.0
 Engine: Linux / MergerFS Read-Only Storage Auditor
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Staging / Downloads: /mnt/pool/downloads
 Organized Library #1: /mnt/pool/media/tv
 Organized Library #2: /mnt/pool/media/movies
 Organized Library #3: /mnt/pool/media/music
 Organized Library #4: /mnt/pool/datasets

 ✔ MergerFS Device Invariant: Single underlying device detected ([66305]). Hardlinks can form atomically.

┌── [1] AUDIT SUMMARY & METRICS ─────────────────────────────────────────────────
│ Total Files Audited:      428,190 (14.28 TiB)
│ Downloads Staging Files:  12,410 (4.10 TiB)
│ Organized Library Files:  415,780 (10.18 TiB)
│ Distinct Inode Keys:      424,310
│
│ Active Normal Hardlinks:  11,940 (3.92 TiB)
│ Orphan Staging Files:     412
│ Ghost Links (Copies):     58
│ Over-Linked Files (>2):   14
│ Ghost Directories:        23
│ TV Sequence Gaps:         4
│ Music Album Gaps:         2
│ Incomplete Datasets:      1
└───────────────────────────────────────────────────────────────────────────────

┌── [2] DOWNLOAD HARDLINK DISCREPANCIES ─────────────────────────────────────────
│ ● Ghost Links (Library st_nlink == 1 matching Downloads name & size): 58
│   ✗ GHOST LINK: /mnt/pool/media/movies/Interstellar (2014)/Interstellar.2014.1080p.mkv (12.40 GiB)
│     ↳ Counterpart: /mnt/pool/downloads/Interstellar.2014.1080p.mkv
│     ↳ File in library has st_nlink=1 matching staging file of identical name/size. [Same Device Copy]
│       A duplicate copy occurred rather than a hardlink (common MergerFS cross-branch failure).
...
```

---

## ⚠️ Important Note: Auditing Over SMB / NFS

**Do not run this tool over an SMB/CIFS mount.**

1. **Synthetic `st_dev`**: The Linux CIFS client assigns a single virtual device ID to the whole share, completely blinding the auditor to whether files cross underlying MergerFS branches (`/mnt/disk1` vs `/mnt/disk2`).
2. **Inode Collisions**: Multiple underlying disks in a MergerFS pool can have colliding inode numbers. Over SMB with a single virtual device, unrelated files may falsely appear hardlinked.
3. **`st_nlink` Inaccuracy**: SMB servers and CIFS clients frequently report `st_nlink == 1` for all regular files unless experimental POSIX extensions are negotiated.
4. **Network Serialization Penalty**: Scanning hundreds of thousands of files over SMB incurs massive latency penalties (minutes to hours vs. seconds locally).

👉 **Recommendation**: Always run `audit-storage` **locally on the storage server host** (e.g. via SSH).

---

## 🧪 Test Suite

Run the built-in regression test suite:

```bash
python3 -m unittest test_audit_storage.py -v
```

The test suite validates:
- Hardlinks (`st_nlink == 1, 2, >2`) and ghost link copy detection.
- Non-duplicative top-down ghost directory residue identification.
- TV sequence gap and single-file orphan season detection.
- Music album missing track numbering.
- Computer vision and NLP dataset split heuristics.
- Pre- and post-audit SHA-256 tree hashing verifying **zero-modification** safety.

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
