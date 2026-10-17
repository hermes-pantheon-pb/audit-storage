#!/usr/bin/env python3
"""
audit_storage.py - High-Performance Linux Storage & MergerFS Audit CLI

A read-only, streaming diagnostic tool to audit storage pools, hardlink invariants,
and media/dataset completeness across staging/download and library trees.
Designed for Linux environments utilizing MergerFS across underlying branch disks.

Standard Library only: Python 3.10+
Zero modifications, moves, or deletions.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
import datetime
import fnmatch
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple


# ==============================================================================
# Configuration & Constants
# ==============================================================================

TOOL_NAME = "audit_storage"
TOOL_VERSION = "1.0.0"

# Common subtitle, metadata, and artwork residue extensions
RESIDUE_EXTENSIONS: Set[str] = {
    # Subtitles
    ".srt", ".sub", ".idx", ".vtt", ".ass", ".ssa", ".smi",
    # Metadata & Checksums
    ".nfo", ".txt", ".sfv", ".xml", ".json", ".url", ".cue",
    ".md5", ".sha1", ".sha256", ".log", ".chrs",
    # Artwork & Posters
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".tbn", ".bmp", ".ico",
    # Partial / Staging residue
    ".part", ".torrent",
}

# Recognized primary media & dataset payload extensions
PAYLOAD_EXTENSIONS: Set[str] = {
    # Video
    ".mkv", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".m4v",
    ".ts", ".m2ts", ".vob", ".iso", ".webm", ".mpg", ".mpeg", ".rmvb",
    # High-quality & Compressed Audio
    ".flac", ".wav", ".alac", ".ape", ".dff", ".dsf",
    ".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wma",
    # Archives & Disk Images
    ".rar", ".zip", ".7z", ".tar", ".gz", ".xz", ".tgz",
    ".bz2", ".zst", ".bin", ".img",
    # Machine Learning / Scientific Datasets
    ".h5", ".hdf5", ".parquet", ".arrow", ".pt", ".pth",
    ".onnx", ".tflite", ".tfrecord", ".npy", ".npz", ".feather",
}

# Audio extensions specifically tracked for music album sequencing
AUDIO_EXTENSIONS: Set[str] = {
    ".flac", ".mp3", ".m4a", ".aac", ".ogg", ".opus",
    ".alac", ".wav", ".aiff", ".ape", ".wma",
}

# Video extensions tracked for TV series sequencing
VIDEO_EXTENSIONS: Set[str] = {
    ".mkv", ".mp4", ".avi", ".mov", ".wmv", ".flv",
    ".m4v", ".ts", ".m2ts", ".webm", ".mpg", ".mpeg",
}

# Regular expressions for TV episode parsing
# Matches S01E02, Season 1 Episode 2, S01E01E02, S01E01-E03, etc.
RE_S_E = re.compile(
    r"(?i)(?:^|[\s._\-\[])(?:s|season\s*)0*(\d{1,4})"
    r"((?:[\s._\-]*(?:e|ep|episode\s*)0*\d{1,4})+)"
)
RE_EP_NUM = re.compile(r"(?i)(?:e|ep|episode\s*)0*(\d{1,4})")
RE_SEASON_X_EP = re.compile(
    r"(?i)(?:^|[\s._\-\[])0*(\d{1,2})x0*(\d{1,3})(?:[\s._\-\]]|$)"
)
RE_SEASON_DIR = re.compile(
    r"(?i)^(?:season|series|s)\s*0*(\d{1,4})$"
)

# Regular expressions for Music track parsing
RE_DISC_TRACK = re.compile(
    r"^(?:(?:(?:cd|disc)[\s._\-]*0*(?P<disc1>\d{1,2})[\s._\-]+)|(?P<disc2>\d{1,2})[\-_.\s])?"
    r"0*(?P<track>\d{1,3})[\s._\-]+",
    re.IGNORECASE,
)
RE_TRACK_PREFIX = re.compile(
    r"(?i)^(?:track|trk)[\s._\-]*0*(?P<track>\d{1,3})[\s._\-]+"
)


# ==============================================================================
# Terminal Color Formatting
# ==============================================================================

class Palette:
    """ANSI color codes with automatic detection for TTY and NO_COLOR."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

    enabled = True

    @classmethod
    def setup(cls, force_no_color: bool = False) -> None:
        if force_no_color or "NO_COLOR" in os.environ or not sys.stdout.isatty():
            cls.enabled = False
            for attr in list(cls.__dict__.keys()):
                if not attr.startswith("__") and isinstance(getattr(cls, attr), str):
                    setattr(cls, attr, "")

    @classmethod
    def c(cls, text: str, color: str) -> str:
        return f"{color}{text}{cls.RESET}" if cls.enabled else text


def format_bytes(num_bytes: int) -> str:
    """Formats raw byte counts into human-readable binary prefixes."""
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    val = float(num_bytes)
    for unit in units:
        if abs(val) < 1024.0 or unit == units[-1]:
            return f"{val:.2f} {unit}" if unit != "B" else f"{int(val)} B"
        val /= 1024.0
    return f"{num_bytes} B"


# ==============================================================================
# Data Models
# ==============================================================================

@dataclass(slots=True)
class FileRecord:
    path: str
    name: str
    dev: int
    ino: int
    nlink: int
    size: int
    is_download: bool


@dataclass
class HardlinkAnomaly:
    category: str  # 'orphan_staging', 'ghost_link', 'over_linked'
    path: str
    name: str
    size: int
    size_human: str
    dev: int
    ino: int
    nlink: int
    counterpart_paths: List[str] = field(default_factory=list)
    details: str = ""


@dataclass
class OverlinkedInodeGroup:
    dev: int
    ino: int
    st_nlink: int
    downloads_count: int
    libraries_count: int
    external_count: int
    downloads_paths: List[str]
    library_paths: List[str]
    size: int
    size_human: str
    sample_name: str
    inferred_cause: str  # 'cross_seeding', 'external_snapshot', 'multi_library', 'dedup_consolidation', 'multi_link'
    details: str


@dataclass
class OverlinkInferenceReport:
    total_unique_inodes: int
    total_tracked_paths: int
    total_bytes: int
    total_bytes_human: str
    physical_sanity_verified: bool
    inode_collision_detected: bool
    collision_details: List[str]
    cause_breakdown: Dict[str, int]
    top_cross_seed_folders: List[Dict[str, Any]]
    link_histogram: Dict[str, int]
    extension_profile: Dict[str, int]


@dataclass
class GhostDirectory:
    path: str
    residue_count: int
    total_residue_size: int
    total_residue_size_human: str
    sample_residue_files: List[str]
    is_empty: bool = False
    details: str = ""


@dataclass
class TVSequenceGap:
    series_name: str
    season: int
    directory: str
    present_episodes: List[int]
    missing_episodes: List[int]
    is_orphan_season: bool
    details: str


@dataclass
class MusicAlbumGap:
    album_name: str
    directory: str
    disc: Optional[int]
    present_tracks: List[int]
    missing_tracks: List[int]
    details: str


@dataclass
class DatasetInconsistency:
    dataset_name: str
    directory: str
    issue_type: str  # 'missing_labels', 'missing_images', 'train_only', 'missing_manifest', 'empty_split'
    details: str


@dataclass
class MergerFSSafetyReport:
    download_devs: List[int]
    library_devs: List[int]
    all_devs: List[int]
    cross_device_detected: bool
    warnings: List[str]


# ==============================================================================
# Streaming Traversal Engine
# ==============================================================================

class StorageAuditor:
    """
    Orchestrates the read-only audit of staging and library storage trees.
    Utilizes os.scandir for streaming, memory-efficient traversal.
    """

    def __init__(
        self,
        downloads_dir: str,
        library_dirs: List[str],
        exclude_downloads: Optional[List[str]] = None,
        payload_threshold_bytes: int = 100 * 1024 * 1024,
        verbose: bool = False,
    ):
        self.downloads_dir = str(Path(downloads_dir).resolve())
        self.library_dirs = [str(Path(p).resolve()) for p in library_dirs]
        self.exclude_downloads: List[str] = list(exclude_downloads or [])
        self.skipped_download_dirs: List[str] = []
        self.payload_threshold = payload_threshold_bytes
        self.verbose = verbose

        # Metrics
        self.total_scanned_files = 0
        self.total_scanned_bytes = 0
        self.downloads_file_count = 0
        self.downloads_total_bytes = 0
        self.library_file_count = 0
        self.library_total_bytes = 0

        # Inode registry: (dev, ino) -> {"downloads": [FileRecord], "libraries": [FileRecord]}
        self.inode_map: Dict[Tuple[int, int], Dict[str, List[FileRecord]]] = defaultdict(
            lambda: {"downloads": [], "libraries": []}
        )

        # Index download files by (name, size) and size for Ghost Link (copy vs hardlink) detection
        self.downloads_by_name_size: Dict[Tuple[str, int], List[FileRecord]] = defaultdict(list)
        self.downloads_by_size: Dict[int, List[FileRecord]] = defaultdict(list)

        # Collections of flagged findings
        self.orphan_staging_files: List[HardlinkAnomaly] = []
        self.ghost_links: List[HardlinkAnomaly] = []
        self.over_linked_files: List[HardlinkAnomaly] = []
        self.over_linked_groups: List[OverlinkedInodeGroup] = []
        self.normal_hardlinks_count = 0
        self.normal_hardlinks_bytes = 0
        self.normal_with_external_snapshots_count = 0

        # Inode collision and inference diagnostics
        self.inode_collision_detected = False
        self.inode_collisions: List[str] = []
        self.overlink_inference: Optional[OverlinkInferenceReport] = None

        self.ghost_directories: List[GhostDirectory] = []
        self.tv_gaps: List[TVSequenceGap] = []
        self.music_gaps: List[MusicAlbumGap] = []
        self.dataset_inconsistencies: List[DatasetInconsistency] = []

        # Device mapping
        self.download_devs: Set[int] = set()
        self.library_devs: Set[int] = set()
        self.scan_errors: List[str] = []

    def run(self) -> None:
        """Executes the full audit workflow."""
        # 1. Stream scan downloads
        self._scan_downloads()

        # 2. Stream scan libraries (collect files, evaluate directory structures)
        self._scan_libraries()

        # 3. Analyze Hardlink Invariants & Ghost Links
        self._analyze_hardlink_invariants()

    # --------------------------------------------------------------------------
    # Directory Traversal
    # --------------------------------------------------------------------------

    def _is_download_dir_excluded(self, dirpath: str) -> bool:
        """
        Determines whether a download subdirectory matches any exclusion rule or pattern.
        Supports:
          - Directory name (basename): e.g. 'incomplete', 'temp', '.recycle'
          - Relative path from downloads: e.g. 'torrents/incomplete', 'usenet/intermediate'
          - Glob patterns: e.g. '*temp*', '*.tmp', 'manual*'
          - Absolute or normalized paths
        """
        if not self.exclude_downloads:
            return False

        norm_path = os.path.normpath(dirpath)
        if norm_path == self.downloads_dir:
            return False

        base_name = os.path.basename(norm_path)
        try:
            rel_path = os.path.relpath(norm_path, self.downloads_dir)
        except ValueError:
            rel_path = norm_path

        rel_parts = Path(rel_path).parts if rel_path != "." else ()

        for raw_pat in self.exclude_downloads:
            pat = raw_pat.strip()
            if not pat:
                continue
            clean_pat = os.path.normpath(pat).rstrip("/\\")

            # 1. Exact match against directory base name
            if base_name == clean_pat or base_name == pat.rstrip("/\\"):
                return True

            # 2. Exact match against relative path or full path
            if rel_path == clean_pat or norm_path == clean_pat:
                return True

            # 3. Path component match (e.g. if pattern is 'incomplete' and path is 'torrents/incomplete')
            if clean_pat in rel_parts:
                return True

            # 4. Glob pattern match against directory base name (e.g. '*temp*', 'incomplete*')
            if fnmatch.fnmatch(base_name, clean_pat):
                return True

            # 5. Glob pattern match against relative path (e.g. 'torrents/*', '*/incomplete')
            if fnmatch.fnmatch(rel_path, clean_pat):
                return True

            # 6. Absolute path resolution
            try:
                if Path(norm_path).resolve() == Path(clean_pat).resolve():
                    return True
            except Exception:
                pass

        return False

    def _walk_tree_postorder(
        self,
        root_path: str,
        exclude_dir_predicate: Optional[Callable[[str], bool]] = None,
        on_dir_excluded: Optional[Callable[[str], None]] = None,
    ) -> Iterator[Tuple[str, List[os.DirEntry], List[str]]]:
        """
        Iterative post-order traversal using os.scandir.
        Yields (current_dir, [file_DirEntries], [child_dir_paths]).
        Ensures children are visited and evaluated before their parent directory.
        Allows pruning subdirectories if exclude_dir_predicate matches.
        """
        stack: List[Tuple[str, int]] = [(root_path, 0)]
        cached_dirs: Dict[str, List[str]] = {}
        cached_files: Dict[str, List[os.DirEntry]] = {}

        while stack:
            curr_dir, state = stack.pop()
            if state == 0:
                subdirs: List[str] = []
                files: List[os.DirEntry] = []
                try:
                    with os.scandir(curr_dir) as it:
                        for entry in it:
                            try:
                                if entry.is_dir(follow_symlinks=False):
                                    if exclude_dir_predicate and exclude_dir_predicate(entry.path):
                                        if on_dir_excluded:
                                            on_dir_excluded(entry.path)
                                        continue
                                    subdirs.append(entry.path)
                                elif entry.is_file(follow_symlinks=False):
                                    files.append(entry)
                            except OSError as e:
                                self.scan_errors.append(f"Stat error on {entry.path}: {e}")
                                continue
                except OSError as e:
                    self.scan_errors.append(f"Access error scanning {curr_dir}: {e}")
                    continue

                cached_dirs[curr_dir] = subdirs
                cached_files[curr_dir] = files
                stack.append((curr_dir, 1))
                for s in reversed(subdirs):
                    stack.append((s, 0))
            else:
                subdirs = cached_dirs.pop(curr_dir, [])
                files = cached_files.pop(curr_dir, [])
                yield curr_dir, files, subdirs

    def _scan_downloads(self) -> None:
        """Indexes all regular files in the staging/download tree."""
        if not os.path.exists(self.downloads_dir):
            raise FileNotFoundError(f"Downloads directory does not exist: {self.downloads_dir}")

        try:
            root_stat = os.stat(self.downloads_dir)
            self.download_devs.add(root_stat.st_dev)
        except OSError as e:
            self.scan_errors.append(f"Cannot stat downloads root: {e}")

        for dirpath, file_entries, _ in self._walk_tree_postorder(
            self.downloads_dir,
            exclude_dir_predicate=self._is_download_dir_excluded,
            on_dir_excluded=self.skipped_download_dirs.append,
        ):
            for entry in file_entries:
                try:
                    stat_res = entry.stat(follow_symlinks=False)
                except OSError as e:
                    self.scan_errors.append(f"Stat error on {entry.path}: {e}")
                    continue

                rec = FileRecord(
                    path=entry.path,
                    name=entry.name,
                    dev=stat_res.st_dev,
                    ino=stat_res.st_ino,
                    nlink=stat_res.st_nlink,
                    size=stat_res.st_size,
                    is_download=True,
                )

                self.download_devs.add(rec.dev)
                self.downloads_file_count += 1
                self.downloads_total_bytes += rec.size
                self.total_scanned_files += 1
                self.total_scanned_bytes += rec.size

                key = (rec.dev, rec.ino)
                self.inode_map[key]["downloads"].append(rec)
                self.downloads_by_name_size[(rec.name, rec.size)].append(rec)
                self.downloads_by_size[rec.size].append(rec)

    def _scan_libraries(self) -> None:
        """
        Traverses library trees, indexing files into the inode map and evaluating
        structural heuristics (Ghost Dirs, TV sequences, Music tracks, Datasets).
        """
        for lib_root in self.library_dirs:
            if not os.path.exists(lib_root):
                raise FileNotFoundError(f"Library directory does not exist: {lib_root}")

            try:
                root_stat = os.stat(lib_root)
                self.library_devs.add(root_stat.st_dev)
            except OSError as e:
                self.scan_errors.append(f"Cannot stat library root {lib_root}: {e}")

            # Subtree tracking for ghost directory (residue) analysis:
            # maps dirpath -> (has_payload, residue_count, residue_size, sample_files)
            dir_subtree_info: Dict[str, Tuple[bool, int, int, List[str]]] = {}
            cached_dir_subdirs: Dict[str, List[str]] = {}

            # TV episode tracker per season: (series_dir, season_num) -> list of (ep_num, filename)
            tv_series_seasons: Dict[Tuple[str, int], List[Tuple[int, str]]] = defaultdict(list)

            for dirpath, file_entries, subdirs in self._walk_tree_postorder(lib_root):
                cached_dir_subdirs[dirpath] = subdirs
                dir_has_direct_payload = False
                direct_residue_count = 0
                direct_residue_size = 0
                direct_residue_samples: List[str] = []

                dir_audio_files: List[Tuple[str, int]] = []  # (filename, size)

                for entry in file_entries:
                    try:
                        stat_res = entry.stat(follow_symlinks=False)
                    except OSError as e:
                        self.scan_errors.append(f"Stat error on {entry.path}: {e}")
                        continue

                    rec = FileRecord(
                        path=entry.path,
                        name=entry.name,
                        dev=stat_res.st_dev,
                        ino=stat_res.st_ino,
                        nlink=stat_res.st_nlink,
                        size=stat_res.st_size,
                        is_download=False,
                    )

                    self.library_devs.add(rec.dev)
                    self.library_file_count += 1
                    self.library_total_bytes += rec.size
                    self.total_scanned_files += 1
                    self.total_scanned_bytes += rec.size

                    key = (rec.dev, rec.ino)
                    self.inode_map[key]["libraries"].append(rec)

                    ext = Path(rec.name).suffix.lower()

                    # Check payload vs residue
                    is_payload = (
                        rec.size >= self.payload_threshold
                        or (ext in PAYLOAD_EXTENSIONS and rec.size >= 1024 * 1024)
                    )

                    if is_payload:
                        dir_has_direct_payload = True
                    elif ext in RESIDUE_EXTENSIONS or rec.size < 512 * 1024:
                        direct_residue_count += 1
                        direct_residue_size += rec.size
                        if len(direct_residue_samples) < 5:
                            direct_residue_samples.append(rec.name)

                    # TV Episode detection (on video files or files > 20MB)
                    if ext in VIDEO_EXTENSIONS or rec.size > 20 * 1024 * 1024:
                        self._extract_tv_episode(dirpath, rec.name, tv_series_seasons)

                    # Music Track collection
                    if ext in AUDIO_EXTENSIONS:
                        dir_audio_files.append((rec.name, rec.size))

                # Aggregate subtree payload and residue metrics from child subdirectories
                child_payload = False
                child_residue_count = 0
                child_residue_size = 0
                child_residue_samples: List[str] = []

                for sub in subdirs:
                    if sub in dir_subtree_info:
                        has_p, r_cnt, r_sz, r_samples = dir_subtree_info[sub]
                        if has_p:
                            child_payload = True
                        child_residue_count += r_cnt
                        child_residue_size += r_sz
                        for s in r_samples:
                            if len(child_residue_samples) < 5:
                                rel = os.path.relpath(os.path.join(sub, s), dirpath)
                                child_residue_samples.append(rel)

                subtree_has_payload = dir_has_direct_payload or child_payload
                total_residue_count = direct_residue_count + child_residue_count
                total_residue_size = direct_residue_size + child_residue_size
                combined_samples = (direct_residue_samples + child_residue_samples)[:5]

                dir_subtree_info[dirpath] = (
                    subtree_has_payload,
                    total_residue_count,
                    total_residue_size,
                    combined_samples,
                )

                # Heuristic 2: Music Album track sequence check
                if len(dir_audio_files) >= 2:
                    self._check_music_album(dirpath, dir_audio_files)

                # Heuristic 3: Dataset completeness check
                subdir_basenames = [os.path.basename(s) for s in subdirs]
                file_basenames = [entry.name for entry in file_entries]
                self._check_dataset_structure(dirpath, subdir_basenames, file_basenames)

            # Find top-level ghost directories (eliminating nested subfolder duplicates)
            self._identify_top_level_ghost_dirs(lib_root, dir_subtree_info, cached_dir_subdirs)

            # Heuristic 4: TV Series sequence gaps & orphan seasons evaluation
            self._evaluate_tv_series_gaps(tv_series_seasons)

    def _identify_top_level_ghost_dirs(
        self,
        lib_root: str,
        dir_subtree_info: Dict[str, Tuple[bool, int, int, List[str]]],
        cached_dir_subdirs: Dict[str, List[str]],
    ) -> None:
        """
        Top-down traversal to identify highest-level ghost directories.
        Prevents nested child duplicates: if a parent folder has zero payloads,
        only the top-level folder is reported.
        """
        def visit(curr: str) -> None:
            has_p, r_cnt, r_sz, r_samples = dir_subtree_info.get(curr, (True, 0, 0, []))
            subdirs = cached_dir_subdirs.get(curr, [])

            # Don't classify pure dataset directories as media ghost directories
            dirname_lower = os.path.basename(curr).lower()
            split_subdirs = {os.path.basename(s).lower() for s in subdirs}
            dataset_marker_set = {
                "train", "training", "val", "valid", "validation", "test", "testing",
                "labels", "label", "annotations", "annot", "masks",
                "images", "image", "imgs", "img", "jpegimages"
            }
            if (split_subdirs & dataset_marker_set) or (dirname_lower in dataset_marker_set):
                for s in subdirs:
                    visit(s)
                return

            if not has_p:
                if curr == lib_root:
                    # If the library root itself has subdirs, inspect children
                    if subdirs:
                        for s in subdirs:
                            visit(s)
                        return
                    elif r_cnt == 0:
                        # Completely empty library root
                        return

                # Top-level ghost directory found
                is_empty = (r_cnt == 0)
                self.ghost_directories.append(
                    GhostDirectory(
                        path=curr,
                        residue_count=r_cnt,
                        total_residue_size=r_sz,
                        total_residue_size_human=format_bytes(r_sz),
                        sample_residue_files=r_samples,
                        is_empty=is_empty,
                        details=(
                            "Empty directory with no payload files."
                            if is_empty
                            else f"Contains {r_cnt} residue file(s) ({format_bytes(r_sz)}) and 0 media/dataset payloads."
                        ),
                    )
                )
                # Do not recurse into children of an already flagged ghost directory
                return

            # Parent has payloads: inspect child directories
            for s in subdirs:
                visit(s)

        visit(lib_root)


    # --------------------------------------------------------------------------
    # Inode & Hardlink Audit Logic
    # --------------------------------------------------------------------------

    def _analyze_hardlink_invariants(self) -> None:
        """
        Audits hardlink invariants across downloads and libraries:
        1. st_nlink == 1 in downloads -> Orphaned staging file
        2. st_nlink == 2 in downloads -> Normal active hardlink (verified against library)
        3. st_nlink > 2 in downloads -> Over-linked file
        4. Ghost Links: Library file with st_nlink == 1 matching a download file by name & size.
        """
        # Set to track files already classified as ghost links
        ghost_link_download_paths: Set[str] = set()

        # Step A: Identify Ghost Links (Library file st_nlink == 1, matching download name & size or byte size for payloads)
        for (dev, ino), data in self.inode_map.items():
            lib_records = data["libraries"]
            if not lib_records:
                continue

            for lib_rec in lib_records:
                if lib_rec.nlink == 1:
                    # 1. Look up if an identical filename + size file exists in downloads
                    candidates = self.downloads_by_name_size.get((lib_rec.name, lib_rec.size), [])
                    renamed = False

                    # 2. Fallback: Exact byte size match for large payloads (>= 10MB) even if renamed on import
                    if not candidates and lib_rec.size >= 10 * 1024 * 1024:
                        size_candidates = self.downloads_by_size.get(lib_rec.size, [])
                        candidates = [
                            c for c in size_candidates
                            if Path(c.name).suffix.lower() == Path(lib_rec.name).suffix.lower()
                            or Path(c.name).suffix.lower() in PAYLOAD_EXTENSIONS
                        ]
                        if candidates:
                            renamed = True

                    for dl_rec in candidates:
                        # If different inode or device, they are NOT hardlinked: it is a duplicate copy!
                        if (dl_rec.dev != lib_rec.dev) or (dl_rec.ino != lib_rec.ino):
                            cross_dev_note = (
                                " [Cross-Device EXDEV]" if dl_rec.dev != lib_rec.dev else " [Same Device Copy]"
                            )
                            rename_note = f" under different name '{dl_rec.name}'" if renamed else ""
                            self.ghost_links.append(
                                HardlinkAnomaly(
                                    category="ghost_link",
                                    path=lib_rec.path,
                                    name=lib_rec.name,
                                    size=lib_rec.size,
                                    size_human=format_bytes(lib_rec.size),
                                    dev=lib_rec.dev,
                                    ino=lib_rec.ino,
                                    nlink=lib_rec.nlink,
                                    counterpart_paths=[dl_rec.path],
                                    details=(
                                        f"File in library has st_nlink=1 matching staging file of identical size{rename_note}.{cross_dev_note} "
                                        f"A duplicate copy occurred rather than a hardlink (common MergerFS cross-branch failure)."
                                    ),
                                )
                            )
                            ghost_link_download_paths.add(dl_rec.path)
                            break

        # Step B: Analyze Inode Link Topologies & Invariants
        cross_seed_pair_counter: Counter[Tuple[str, str]] = Counter()
        link_hist: Counter[int] = Counter()
        ext_counter: Counter[str] = Counter()
        cause_counter: Counter[str] = Counter()

        for (dev, ino), data in self.inode_map.items():
            dl_records = data["downloads"]
            lib_records = data["libraries"]
            if not dl_records:
                continue

            all_records = dl_records + lib_records
            ref_size = all_records[0].size
            # Sanity check: verify physical inode size consistency across all appearances
            for r in all_records[1:]:
                if r.size != ref_size:
                    self.inode_collision_detected = True
                    self.inode_collisions.append(
                        f"Collision on (dev={dev}, ino={ino}): '{all_records[0].path}' ({format_bytes(ref_size)}) vs '{r.path}' ({format_bytes(r.size)})"
                    )

            D = len(dl_records)
            L = len(lib_records)
            T = D + L
            st_nlink = dl_records[0].nlink
            E = max(0, st_nlink - T)

            sample_rec = dl_records[0]
            dl_paths = [r.path for r in dl_records]
            lib_paths = [r.path for r in lib_records]
            ext = Path(sample_rec.name).suffix.lower()

            # Case 1: Orphan Staging (Zero paths in library)
            if L == 0:
                for dl_rec in dl_records:
                    is_ghost_cp = dl_rec.path in ghost_link_download_paths
                    if is_ghost_cp:
                        details = "Staging file copied to library instead of hardlinked (ghost link counterpart)."
                    elif D > 1:
                        details = f"Multi-staged orphan: present across {D} locations in downloads, but 0 in organized library."
                    elif E > 0:
                        details = f"Staging file has {st_nlink} links on disk ({E} external), but 0 in organized library."
                    else:
                        details = "Orphaned staging file. Has no hardlink in organized library (st_nlink == 1)."

                    self.orphan_staging_files.append(
                        HardlinkAnomaly(
                            category="orphan_staging",
                            path=dl_rec.path,
                            name=dl_rec.name,
                            size=dl_rec.size,
                            size_human=format_bytes(dl_rec.size),
                            dev=dl_rec.dev,
                            ino=dl_rec.ino,
                            nlink=dl_rec.nlink,
                            counterpart_paths=lib_paths,
                            details=details,
                        )
                    )
                continue

            # Case 2: Healthy 1:1 Link (1 in downloads, 1 in library)
            if D == 1 and L == 1:
                self.normal_hardlinks_count += 1
                self.normal_hardlinks_bytes += sample_rec.size
                if E > 0:
                    self.normal_with_external_snapshots_count += 1
                continue

            # Case 3: Over-Linked / Multi-Linked Inode (D > 1, or L > 1, or st_nlink > 2 with multiple tracked paths)
            # Inferred Root Cause:
            if st_nlink >= 10:
                inferred_cause = "dedup_consolidation"
                details = (
                    f"High-density deduplication link: {st_nlink} physical links "
                    f"({D} in downloads, {L} in library, {E} external). "
                    f"Common result of deduplication utilities (jdupes/rmlint) consolidating identical files."
                )
            elif D > 1 and L >= 1:
                inferred_cause = "cross_seeding"
                rel_folders = set()
                for p in dl_paths:
                    rel = os.path.relpath(p, self.downloads_dir)
                    parts = Path(rel).parts
                    if len(parts) > 1:
                        rel_folders.add(parts[0])
                    else:
                        rel_folders.add("downloads_root")
                if len(rel_folders) > 1:
                    sorted_folders = sorted(rel_folders)
                    for i in range(len(sorted_folders)):
                        for j in range(i + 1, len(sorted_folders)):
                            cross_seed_pair_counter[(sorted_folders[i], sorted_folders[j])] += 1
                    folder_str = " ↔ ".join(f"'{f}'" for f in sorted(rel_folders)[:3])
                    details = (
                        f"Cross-seeded across {D} download folders ({folder_str}), "
                        f"linked to {L} library location(s) [st_nlink={st_nlink}, {E} external]."
                    )
                else:
                    details = (
                        f"Duplicated across {D} paths within '{list(rel_folders)[0]}', "
                        f"linked to {L} library location(s) [st_nlink={st_nlink}, {E} external]."
                    )
            elif D >= 1 and L > 1:
                inferred_cause = "multi_library"
                details = (
                    f"Multi-library linked: present in {L} library destinations and {D} download location(s) "
                    f"[st_nlink={st_nlink}, {E} external]."
                )
            else:
                inferred_cause = "external_snapshot"
                details = (
                    f"File has {st_nlink} physical links ({D} in downloads, {L} in library, {E} external). "
                    f"External links reside outside scanned trees (e.g. backup snapshots)."
                )

            group = OverlinkedInodeGroup(
                dev=dev,
                ino=ino,
                st_nlink=st_nlink,
                downloads_count=D,
                libraries_count=L,
                external_count=E,
                downloads_paths=dl_paths,
                library_paths=lib_paths,
                size=sample_rec.size,
                size_human=format_bytes(sample_rec.size),
                sample_name=sample_rec.name,
                inferred_cause=inferred_cause,
                details=details,
            )
            self.over_linked_groups.append(group)

            for r in dl_records:
                counterparts = [p for p in dl_paths if p != r.path] + lib_paths
                self.over_linked_files.append(
                    HardlinkAnomaly(
                        category="over_linked",
                        path=r.path,
                        name=r.name,
                        size=r.size,
                        size_human=format_bytes(r.size),
                        dev=r.dev,
                        ino=r.ino,
                        nlink=r.nlink,
                        counterpart_paths=counterparts,
                        details=details,
                    )
                )

            link_hist[st_nlink] += 1
            ext_counter[ext or "none"] += 1
            cause_counter[inferred_cause] += 1

        # Build OverlinkInferenceReport
        top_cross_seeds = [
            {"folder_a": p[0], "folder_b": p[1], "shared_inodes": count}
            for p, count in cross_seed_pair_counter.most_common(5)
        ]
        top_exts = dict(ext_counter.most_common(5))
        hist_dict = {str(k): v for k, v in sorted(link_hist.items())}

        total_bytes = sum(g.size for g in self.over_linked_groups)
        total_paths = sum(g.downloads_count + g.libraries_count for g in self.over_linked_groups)

        self.overlink_inference = OverlinkInferenceReport(
            total_unique_inodes=len(self.over_linked_groups),
            total_tracked_paths=total_paths,
            total_bytes=total_bytes,
            total_bytes_human=format_bytes(total_bytes),
            physical_sanity_verified=(not self.inode_collision_detected),
            inode_collision_detected=self.inode_collision_detected,
            collision_details=self.inode_collisions[:5],
            cause_breakdown=dict(cause_counter),
            top_cross_seed_folders=top_cross_seeds,
            link_histogram=hist_dict,
            extension_profile=top_exts,
        )

    # --------------------------------------------------------------------------
    # TV Series Sequence Heuristics
    # --------------------------------------------------------------------------

    def _extract_tv_episode(
        self,
        dirpath: str,
        filename: str,
        tv_series_seasons: Dict[Tuple[str, int], List[Tuple[int, str]]],
    ) -> None:
        """Parses season and episode indices from TV media files."""
        # Check standard SxxEyy
        m_se = RE_S_E.search(filename)
        season: Optional[int] = None
        episodes: List[int] = []

        if m_se:
            season = int(m_se.group(1))
            episodes = [int(x) for x in RE_EP_NUM.findall(m_se.group(2))]
        else:
            # Check 1x02 format
            m_x = RE_SEASON_X_EP.search(filename)
            if m_x:
                season = int(m_x.group(1))
                episodes = [int(m_x.group(2))]
            else:
                # Check if parent dir is 'Season XX' and filename starts with episode number
                parent_name = os.path.basename(dirpath)
                m_dir = RE_SEASON_DIR.match(parent_name)
                if m_dir:
                    season = int(m_dir.group(1))
                    m_ep_only = re.search(r"(?:^|[\s._\-\[])0*(\d{1,3})(?:[\s._\-\]]|$)", filename)
                    if m_ep_only:
                        episodes = [int(m_ep_only.group(1))]

        if season is not None and episodes:
            # Determine Series Directory
            # If current dir is Season XX, series dir is parent
            parent_name = os.path.basename(dirpath)
            if RE_SEASON_DIR.match(parent_name):
                series_dir = os.path.dirname(dirpath)
            else:
                series_dir = dirpath

            for ep in episodes:
                tv_series_seasons[(series_dir, season)].append((ep, filename))

    def _evaluate_tv_series_gaps(
        self, tv_series_seasons: Dict[Tuple[str, int], List[Tuple[int, str]]]
    ) -> None:
        """Evaluates detected TV episode sequences for non-continuous gaps and orphan seasons."""
        for (series_dir, season), ep_list in tv_series_seasons.items():
            series_name = os.path.basename(series_dir)
            ep_numbers = sorted(set(ep for ep, _ in ep_list))

            if not ep_numbers:
                continue

            if len(ep_numbers) == 1:
                # Single-file orphan season
                only_ep = ep_numbers[0]
                self.tv_gaps.append(
                    TVSequenceGap(
                        series_name=series_name,
                        season=season,
                        directory=series_dir,
                        present_episodes=ep_numbers,
                        missing_episodes=[],
                        is_orphan_season=True,
                        details=(
                            f"Single-file orphan season detected: only episode S{season:02d}E{only_ep:02d} is present. "
                            f"Possible aborted download or incomplete series import."
                        ),
                    )
                )
            else:
                # Check sequence gaps
                min_ep = min(ep_numbers)
                max_ep = max(ep_numbers)
                # Standard broadcast seasons start at episode 1
                start_ep = 1 if min_ep <= 2 else min_ep
                expected_set = set(range(start_ep, max_ep + 1))
                missing = sorted(expected_set - set(ep_numbers))

                if missing:
                    missing_labels = [f"E{e:02d}" for e in missing]
                    self.tv_gaps.append(
                        TVSequenceGap(
                            series_name=series_name,
                            season=season,
                            directory=series_dir,
                            present_episodes=ep_numbers,
                            missing_episodes=missing,
                            is_orphan_season=False,
                            details=(
                                f"Non-continuous sequence gap in S{season:02d}: missing {len(missing)} episode(s) "
                                f"({', '.join(missing_labels)}) across span E{min_ep:02d}-E{max_ep:02d} ({len(ep_numbers)} present)."
                            ),
                        )
                    )

    # --------------------------------------------------------------------------
    # Music Album Heuristics
    # --------------------------------------------------------------------------

    def _check_music_album(self, album_dir: str, audio_files: List[Tuple[str, int]]) -> None:
        """Parses audio track numbers and identifies missing intermediate tracks."""
        tracks_by_disc: Dict[int, List[int]] = defaultdict(list)

        for filename, _ in audio_files:
            disc = 1
            track: Optional[int] = None

            m_dt = RE_DISC_TRACK.search(filename)
            if m_dt:
                d1 = m_dt.group("disc1")
                d2 = m_dt.group("disc2")
                if d1:
                    disc = int(d1)
                elif d2:
                    disc = int(d2)
                track = int(m_dt.group("track"))
            else:
                m_trk = RE_TRACK_PREFIX.search(filename)
                if m_trk:
                    track = int(m_trk.group("track"))

            if track is not None:
                tracks_by_disc[disc].append(track)

        album_name = os.path.basename(album_dir)

        for disc, track_nums in tracks_by_disc.items():
            unique_tracks = sorted(set(track_nums))
            if len(unique_tracks) < 2:
                continue

            min_t = min(unique_tracks)
            max_t = max(unique_tracks)
            start_t = 1 if min_t <= 2 else min_t
            expected = set(range(start_t, max_t + 1))
            missing = sorted(expected - set(unique_tracks))

            if missing:
                missing_str = [f"{t:02d}" for t in missing]
                disc_note = f" (Disc {disc})" if disc > 1 or len(tracks_by_disc) > 1 else ""
                self.music_gaps.append(
                    MusicAlbumGap(
                        album_name=album_name,
                        directory=album_dir,
                        disc=disc if len(tracks_by_disc) > 1 or disc > 1 else None,
                        present_tracks=unique_tracks,
                        missing_tracks=missing,
                        details=(
                            f"Album '{album_name}'{disc_note}: missing intermediate track(s) "
                            f"{', '.join(missing_str)} between track {min_t:02d} and {max_t:02d} ({len(unique_tracks)} present)."
                        ),
                    )
                )

    # --------------------------------------------------------------------------
    # Dataset Completeness Heuristics
    # --------------------------------------------------------------------------

    def _check_dataset_structure(
        self, dirpath: str, subdirs: List[str], files: List[str]
    ) -> None:
        """
        Evaluates directory contents for patterns indicating machine learning datasets:
        - Image/label pair asymmetry (images/ without labels/)
        - Train/val/test split asymmetry (train/ without val/ or test/)
        - Missing common manifest files (dataset.json, classes.txt, data.yaml)
        """
        # Skip child split subdirectories (e.g. dataset/train or dataset/images)
        dirname_lower = os.path.basename(dirpath).lower()
        if dirname_lower in {
            "train", "training", "val", "valid", "validation", "test", "testing",
            "images", "image", "imgs", "img", "jpegimages", "labels", "label", "annotations", "annot", "masks"
        }:
            return

        sub_lower = {s.lower() for s in subdirs}
        file_lower = {f.lower() for f in files}

        # Check markers
        image_markers = {"images", "image", "imgs", "img", "jpegimages"}
        label_markers = {"labels", "label", "annotations", "annot", "masks"}
        train_markers = {"train", "training"}
        val_markers = {"val", "valid", "validation"}
        test_markers = {"test", "testing"}

        has_images = bool(sub_lower & image_markers)
        has_labels = bool(sub_lower & label_markers)
        has_train = bool(sub_lower & train_markers)
        has_val = bool(sub_lower & val_markers)
        has_test = bool(sub_lower & test_markers)

        # Also check file-level split markers (e.g. train.txt, val.txt)
        file_train = any(f.startswith("train.") or f.startswith("train_") for f in file_lower)
        file_val = any(
            f.startswith("val.") or f.startswith("val_") or f.startswith("valid.") for f in file_lower
        )
        file_test = any(f.startswith("test.") or f.startswith("test_") for f in file_lower)

        has_train = has_train or file_train
        has_val = has_val or file_val
        has_test = has_test or file_test

        # Candidate dataset folder
        dirname_lower = os.path.basename(dirpath).lower()
        is_candidate_dataset = (
            has_images
            or has_labels
            or has_train
            or has_val
            or ("dataset" in dirname_lower)
            or ("data" in dirname_lower and (sub_lower or file_lower))
        )

        if not is_candidate_dataset:
            return

        dataset_name = os.path.basename(dirpath)

        # Check 1: Image / Label pair asymmetry
        if has_images and not has_labels:
            # Check if there is a flat annotation manifest
            has_anno_manifest = any(
                ("annot" in f or "label" in f or "instance" in f)
                and f.endswith((".json", ".xml", ".csv", ".txt", ".yaml", ".yml"))
                for f in file_lower
            )
            if not has_anno_manifest:
                self.dataset_inconsistencies.append(
                    DatasetInconsistency(
                        dataset_name=dataset_name,
                        directory=dirpath,
                        issue_type="missing_labels",
                        details="Contains image directory structure but is missing corresponding 'labels/' or 'annotations/' directory / manifest.",
                    )
                )
        elif has_labels and not has_images:
            self.dataset_inconsistencies.append(
                DatasetInconsistency(
                    dataset_name=dataset_name,
                    directory=dirpath,
                    issue_type="missing_images",
                    details="Contains labels/annotations directory but is missing corresponding 'images/' directory.",
                )
            )

        # Check 2: Train split without validation or test split
        if has_train and not (has_val or has_test):
            self.dataset_inconsistencies.append(
                DatasetInconsistency(
                    dataset_name=dataset_name,
                    directory=dirpath,
                    issue_type="train_only",
                    details="Contains training split ('train/') but lacks validation ('val/') or test ('test/') splits.",
                )
            )

        # Check 3: Missing manifest / class definitions when structured splits exist
        if (has_images and has_labels) or (has_train and has_val):
            manifest_files = {
                "dataset.json", "data.yaml", "data.yml", "classes.txt",
                "labels.txt", "metadata.csv", "dataset_info.json", "coco.json",
            }
            if not (file_lower & manifest_files):
                self.dataset_inconsistencies.append(
                    DatasetInconsistency(
                        dataset_name=dataset_name,
                        directory=dirpath,
                        issue_type="missing_manifest",
                        details="Dataset structure detected, but missing standard metadata manifest (e.g. dataset.json, data.yaml, classes.txt, metadata.csv).",
                    )
                )

    # --------------------------------------------------------------------------
    # MergerFS Safety Verification
    # --------------------------------------------------------------------------

    def get_mergerfs_report(self) -> MergerFSSafetyReport:
        """Generates device invariants and MergerFS cross-branch diagnostics."""
        all_devs = sorted(self.download_devs.union(self.library_devs))
        cross_device = (
            len(self.download_devs.union(self.library_devs)) > 1
            or (bool(self.download_devs) and bool(self.library_devs) and self.download_devs != self.library_devs)
        )

        warnings: List[str] = []
        if cross_device:
            warnings.append(
                f"Multiple filesystem device IDs detected across paths (Downloads: {sorted(self.download_devs)}, Libraries: {sorted(self.library_devs)})."
            )
            warnings.append(
                "POSIX hardlinks CANNOT cross filesystem/branch boundaries (Linux kernel EXDEV error)."
            )
            warnings.append(
                "If using MergerFS: Hardlinks only function when source and destination reside on the exact SAME underlying branch disk."
            )
            warnings.append(
                "Files imported across differing branches will silently fall back to full duplicate copies, causing ghost links and wasted capacity."
            )

        return MergerFSSafetyReport(
            download_devs=sorted(self.download_devs),
            library_devs=sorted(self.library_devs),
            all_devs=all_devs,
            cross_device_detected=cross_device,
            warnings=warnings,
        )

    # --------------------------------------------------------------------------
    # Structured Report Serialization
    # --------------------------------------------------------------------------

    def build_report_dict(self) -> Dict[str, Any]:
        """Constructs an exhaustive dictionary of all audit metrics and findings."""
        mergerfs_report = self.get_mergerfs_report()

        return {
            "metadata": {
                "tool": TOOL_NAME,
                "version": TOOL_VERSION,
                "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "downloads_path": self.downloads_dir,
                "library_paths": self.library_dirs,
                "exclude_downloads": self.exclude_downloads,
                "skipped_download_dirs": self.skipped_download_dirs,
                "payload_threshold_bytes": self.payload_threshold,
                "verbose_mode": self.verbose,
            },
            "summary": {
                "total_files_scanned": self.total_scanned_files,
                "total_bytes_scanned": self.total_scanned_bytes,
                "total_size_human": format_bytes(self.total_scanned_bytes),
                "downloads_file_count": self.downloads_file_count,
                "downloads_total_bytes": self.downloads_total_bytes,
                "downloads_size_human": format_bytes(self.downloads_total_bytes),
                "skipped_download_dirs_count": len(self.skipped_download_dirs),
                "library_file_count": self.library_file_count,
                "library_total_bytes": self.library_total_bytes,
                "library_size_human": format_bytes(self.library_total_bytes),
                "distinct_device_count": len(mergerfs_report.all_devs),
                "cross_device_detected": mergerfs_report.cross_device_detected,
                "counts": {
                    "orphaned_staging_files": len(self.orphan_staging_files),
                    "ghost_links": len(self.ghost_links),
                    "over_linked_files": len(self.over_linked_groups),
                    "over_linked_unique_inodes": len(self.over_linked_groups),
                    "over_linked_total_paths": len(self.over_linked_files),
                    "normal_active_hardlinks": self.normal_hardlinks_count,
                    "normal_with_external_snapshots": self.normal_with_external_snapshots_count,
                    "inode_collision_detected": self.inode_collision_detected,
                    "ghost_directories": len(self.ghost_directories),
                    "tv_sequence_gaps": len(self.tv_gaps),
                    "music_album_gaps": len(self.music_gaps),
                    "dataset_inconsistencies": len(self.dataset_inconsistencies),
                },
            },
            "mergerfs_device_audit": asdict(mergerfs_report),
            "download_hardlink_discrepancies": {
                "normal_active_hardlinks_summary": {
                    "count": self.normal_hardlinks_count,
                    "total_bytes": self.normal_hardlinks_bytes,
                    "total_size_human": format_bytes(self.normal_hardlinks_bytes),
                    "with_external_snapshots": self.normal_with_external_snapshots_count,
                },
                "ghost_links": [asdict(x) for x in self.ghost_links],
                "orphaned_staging_files": [asdict(x) for x in self.orphan_staging_files],
                "over_linked_inference": asdict(self.overlink_inference) if self.overlink_inference else None,
                "over_linked_groups": [asdict(g) for g in self.over_linked_groups],
                "over_linked_files": [asdict(x) for x in self.over_linked_files],
            },
            "suspected_ghost_directories": [asdict(x) for x in self.ghost_directories],
            "structural_media_and_dataset_gaps": {
                "tv_series_gaps": [asdict(x) for x in self.tv_gaps],
                "music_album_gaps": [asdict(x) for x in self.music_gaps],
                "dataset_inconsistencies": [asdict(x) for x in self.dataset_inconsistencies],
            },
            "scan_warnings_and_errors": self.scan_errors,
        }

    def export_separate_reports(self, output_dir: str) -> Dict[str, Any]:
        """
        Exports separate, dedicated diagnostic report files for each anomaly flag category.
        Generates both structured JSON (.json) and clean, shell-friendly plaintext (.txt)
        files in the specified output directory.
        """
        out_path = Path(output_dir).expanduser().resolve()
        out_path.mkdir(parents=True, exist_ok=True)
        manifest: Dict[str, Any] = {
            "output_directory": str(out_path),
            "files": {},
        }

        # 1. Summary
        summary_data = {
            "metadata": {
                "tool": TOOL_NAME,
                "version": TOOL_VERSION,
                "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "downloads_path": self.downloads_dir,
                "library_paths": self.library_dirs,
                "exclude_downloads": self.exclude_downloads,
                "skipped_download_dirs": self.skipped_download_dirs,
                "payload_threshold_bytes": self.payload_threshold,
            },
            "summary": {
                "total_files_scanned": self.total_scanned_files,
                "total_bytes_scanned": self.total_scanned_bytes,
                "total_size_human": format_bytes(self.total_scanned_bytes),
                "downloads_file_count": self.downloads_file_count,
                "downloads_total_bytes": self.downloads_total_bytes,
                "downloads_size_human": format_bytes(self.downloads_total_bytes),
                "skipped_download_dirs_count": len(self.skipped_download_dirs),
                "library_file_count": self.library_file_count,
                "library_total_bytes": self.library_total_bytes,
                "library_size_human": format_bytes(self.library_total_bytes),
                "counts": {
                    "orphaned_staging_files": len(self.orphan_staging_files),
                    "ghost_links": len(self.ghost_links),
                    "over_linked_unique_inodes": len(self.over_linked_groups),
                    "over_linked_total_paths": len(self.over_linked_files),
                    "normal_active_hardlinks": self.normal_hardlinks_count,
                    "ghost_directories": len(self.ghost_directories),
                    "tv_sequence_gaps": len(self.tv_gaps),
                    "music_album_gaps": len(self.music_gaps),
                    "dataset_inconsistencies": len(self.dataset_inconsistencies),
                },
            },
            "mergerfs_device_audit": asdict(self.get_mergerfs_report()),
            "scan_errors": self.scan_errors,
        }
        f_sum_json = out_path / "audit_summary.json"
        with open(f_sum_json, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2)

        f_sum_txt = out_path / "audit_summary.txt"
        with open(f_sum_txt, "w", encoding="utf-8") as f:
            f.write(f"STORAGE POOL & HARDLINK INVARIANT AUDIT SUMMARY v{TOOL_VERSION}\n")
            f.write(f"Timestamp UTC: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n")
            f.write(f"Downloads:     {self.downloads_dir}\n")
            for idx, lib in enumerate(self.library_dirs, 1):
                f.write(f"Library #{idx}:   {lib}\n")
            if self.exclude_downloads:
                f.write(f"Excluded:      {', '.join(self.exclude_downloads)} ({len(self.skipped_download_dirs)} pruned)\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Files Audited:      {self.total_scanned_files} ({format_bytes(self.total_scanned_bytes)})\n")
            f.write(f"Downloads Staging Files:  {self.downloads_file_count} ({format_bytes(self.downloads_total_bytes)})\n")
            f.write(f"Organized Library Files:  {self.library_file_count} ({format_bytes(self.library_total_bytes)})\n")
            f.write(f"Active Normal Hardlinks:  {self.normal_hardlinks_count} ({format_bytes(self.normal_hardlinks_bytes)})\n")
            f.write(f"Orphan Staging Files:     {len(self.orphan_staging_files)}\n")
            f.write(f"Ghost Links (Copies):     {len(self.ghost_links)}\n")
            f.write(f"Over-Linked Inodes:       {len(self.over_linked_groups)} ({len(self.over_linked_files)} paths)\n")
            f.write(f"Ghost Directories:        {len(self.ghost_directories)}\n")
            f.write(f"TV Sequence Gaps:         {len(self.tv_gaps)}\n")
            f.write(f"Music Album Gaps:         {len(self.music_gaps)}\n")
            f.write(f"Dataset Inconsistencies:  {len(self.dataset_inconsistencies)}\n")
        manifest["files"]["summary"] = {"json": str(f_sum_json), "txt": str(f_sum_txt)}

        # 2. Orphan Staging Files
        orphans_json_data = [asdict(x) for x in self.orphan_staging_files]
        f_orph_json = out_path / "orphaned_staging_files.json"
        with open(f_orph_json, "w", encoding="utf-8") as f:
            json.dump(orphans_json_data, f, indent=2)

        f_orph_txt = out_path / "orphaned_staging_files.txt"
        with open(f_orph_txt, "w", encoding="utf-8") as f:
            for x in self.orphan_staging_files:
                f.write(f"{x.path}\n")
        manifest["files"]["orphaned_staging_files"] = {
            "count": len(self.orphan_staging_files),
            "json": str(f_orph_json),
            "txt": str(f_orph_txt),
        }

        # 3. Ghost Links (copies instead of hardlinks)
        ghost_json_data = [asdict(x) for x in self.ghost_links]
        f_ghost_json = out_path / "ghost_links.json"
        with open(f_ghost_json, "w", encoding="utf-8") as f:
            json.dump(ghost_json_data, f, indent=2)

        f_ghost_txt = out_path / "ghost_links.txt"
        with open(f_ghost_txt, "w", encoding="utf-8") as f:
            for x in self.ghost_links:
                counterpart = x.counterpart_paths[0] if x.counterpart_paths else "UNKNOWN"
                f.write(f"{x.path}\t{counterpart}\t{x.size_human}\n")
        manifest["files"]["ghost_links"] = {
            "count": len(self.ghost_links),
            "json": str(f_ghost_json),
            "txt": str(f_ghost_txt),
        }

        # 4. Over-Linked Files
        overlink_data = {
            "inference": asdict(self.overlink_inference) if self.overlink_inference else None,
            "unique_inodes_count": len(self.over_linked_groups),
            "total_paths_count": len(self.over_linked_files),
            "groups": [asdict(g) for g in self.over_linked_groups],
            "files": [asdict(x) for x in self.over_linked_files],
        }
        f_over_json = out_path / "over_linked_files.json"
        with open(f_over_json, "w", encoding="utf-8") as f:
            json.dump(overlink_data, f, indent=2)

        f_over_txt = out_path / "over_linked_files.txt"
        with open(f_over_txt, "w", encoding="utf-8") as f:
            if self.overlink_inference:
                causes_str = ", ".join(f"{k}: {v}" for k, v in self.overlink_inference.cause_breakdown.items())
                f.write(f"# CAUSE BREAKDOWN: {causes_str}\n")
                if self.overlink_inference.top_cross_seed_folders:
                    f.write("# TOP CROSS-SEED FOLDERS:\n")
                    for pair in self.overlink_inference.top_cross_seed_folders[:5]:
                        f.write(f"#   - {pair['folders']}: {pair['count']} shared files\n")
                f.write("\n")
            for g in self.over_linked_groups:
                f.write(f"# Inode {g.ino} (dev={g.dev}, nlink={g.st_nlink}, size={format_bytes(g.size)}, cause={g.inferred_cause})\n")
                if g.downloads_paths:
                    f.write("  Downloads:\n")
                    for p in g.downloads_paths:
                        f.write(f"    {p}\n")
                if g.library_paths:
                    f.write("  Libraries:\n")
                    for p in g.library_paths:
                        f.write(f"    {p}\n")
                if g.external_count > 0:
                    f.write(f"  External (outside audit paths): {g.external_count} hardlinks\n")
                f.write("\n")
        manifest["files"]["over_linked_files"] = {
            "unique_inodes": len(self.over_linked_groups),
            "total_paths": len(self.over_linked_files),
            "json": str(f_over_json),
            "txt": str(f_over_txt),
        }

        # 5. Ghost Directories
        ghost_dirs_data = [asdict(x) for x in self.ghost_directories]
        f_gdir_json = out_path / "ghost_directories.json"
        with open(f_gdir_json, "w", encoding="utf-8") as f:
            json.dump(ghost_dirs_data, f, indent=2)

        f_gdir_txt = out_path / "ghost_directories.txt"
        with open(f_gdir_txt, "w", encoding="utf-8") as f:
            for x in self.ghost_directories:
                f.write(f"{x.path}\n")
        manifest["files"]["ghost_directories"] = {
            "count": len(self.ghost_directories),
            "json": str(f_gdir_json),
            "txt": str(f_gdir_txt),
        }

        # 6. TV Sequence Gaps
        tv_gaps_data = [asdict(x) for x in self.tv_gaps]
        f_tv_json = out_path / "tv_sequence_gaps.json"
        with open(f_tv_json, "w", encoding="utf-8") as f:
            json.dump(tv_gaps_data, f, indent=2)

        f_tv_txt = out_path / "tv_sequence_gaps.txt"
        with open(f_tv_txt, "w", encoding="utf-8") as f:
            for x in self.tv_gaps:
                missing_str = ", ".join(f"E{e:02d}" for e in x.missing_episodes)
                min_ep = min(x.present_episodes) if x.present_episodes else 0
                max_ep = max(x.present_episodes) if x.present_episodes else 0
                f.write(f"{x.series_name} / Season {x.season:02d} ({x.directory}) -> Missing: {missing_str} (Present {len(x.present_episodes)} eps: E{min_ep:02d}..E{max_ep:02d})\n")
        manifest["files"]["tv_sequence_gaps"] = {
            "count": len(self.tv_gaps),
            "json": str(f_tv_json),
            "txt": str(f_tv_txt),
        }

        # 7. Music Album Gaps
        music_gaps_data = [asdict(x) for x in self.music_gaps]
        f_music_json = out_path / "music_album_gaps.json"
        with open(f_music_json, "w", encoding="utf-8") as f:
            json.dump(music_gaps_data, f, indent=2)

        f_music_txt = out_path / "music_album_gaps.txt"
        with open(f_music_txt, "w", encoding="utf-8") as f:
            for x in self.music_gaps:
                missing_str = ", ".join(f"Track {t:02d}" for t in x.missing_tracks)
                min_trk = min(x.present_tracks) if x.present_tracks else 0
                max_trk = max(x.present_tracks) if x.present_tracks else 0
                disc_str = f" [Disc {x.disc}]" if x.disc else ""
                f.write(f"{x.album_name}{disc_str} ({x.directory}) -> Missing: {missing_str} (Present {len(x.present_tracks)} tracks: #{min_trk:02d}..#{max_trk:02d})\n")
        manifest["files"]["music_album_gaps"] = {
            "count": len(self.music_gaps),
            "json": str(f_music_json),
            "txt": str(f_music_txt),
        }

        # 8. Dataset Inconsistencies
        dataset_data = [asdict(x) for x in self.dataset_inconsistencies]
        f_ds_json = out_path / "dataset_inconsistencies.json"
        with open(f_ds_json, "w", encoding="utf-8") as f:
            json.dump(dataset_data, f, indent=2)

        f_ds_txt = out_path / "dataset_inconsistencies.txt"
        with open(f_ds_txt, "w", encoding="utf-8") as f:
            for x in self.dataset_inconsistencies:
                f.write(f"{x.dataset_name} ({x.directory})\t[{x.issue_type}]\t{x.details}\n")
        manifest["files"]["dataset_inconsistencies"] = {
            "count": len(self.dataset_inconsistencies),
            "json": str(f_ds_json),
            "txt": str(f_ds_txt),
        }

        # 9. Inode Collisions (if detected)
        if self.inode_collision_detected:
            f_coll_json = out_path / "inode_collisions.json"
            with open(f_coll_json, "w", encoding="utf-8") as f:
                json.dump(self.inode_collisions, f, indent=2)
            f_coll_txt = out_path / "inode_collisions.txt"
            with open(f_coll_txt, "w", encoding="utf-8") as f:
                for c in self.inode_collisions:
                    f.write(f"{c}\n")
            manifest["files"]["inode_collisions"] = {
                "count": len(self.inode_collisions),
                "json": str(f_coll_json),
                "txt": str(f_coll_txt),
            }

        return manifest


# ==============================================================================
# Terminal Presentation Engine
# ==============================================================================

class TerminalReporter:
    """Renders high-visibility, categorized reports formatted for the terminal."""

    def __init__(self, auditor: StorageAuditor, verbose: bool = False):
        self.auditor = auditor
        self.verbose = verbose

    def render(self) -> None:
        """Outputs the categorized diagnostic report to stdout."""
        P = Palette

        self._print_banner()
        self._print_mergerfs_safety()
        self._print_summary_metrics()
        self._print_hardlink_discrepancies()
        self._print_ghost_directories()
        self._print_structural_gaps()
        self._print_footer()

    def _print_banner(self) -> None:
        P = Palette
        print()
        print(P.c("━" * 80, P.CYAN))
        print(
            P.c(" STORAGE POOL & HARDLINK INVARIANT AUDIT REPORT ", P.BOLD + P.WHITE)
            + P.c(f"v{TOOL_VERSION}", P.DIM)
        )
        print(P.c(" Engine: Linux / MergerFS Read-Only Storage Auditor", P.DIM))
        print(P.c("━" * 80, P.CYAN))
        print(f" {P.c('Staging / Downloads:', P.BOLD)} {self.auditor.downloads_dir}")
        for idx, lib in enumerate(self.auditor.library_dirs, 1):
            print(f" {P.c(f'Organized Library #{idx}:', P.BOLD)} {lib}")
        if self.auditor.exclude_downloads:
            pats = ", ".join(f"'{p}'" for p in self.auditor.exclude_downloads)
            print(f" {P.c('Excluded Subdirs:', P.BOLD)} {pats} ({len(self.auditor.skipped_download_dirs)} pruned)")
        print()

    def _print_mergerfs_safety(self) -> None:
        P = Palette
        report = self.auditor.get_mergerfs_report()

        if report.cross_device_detected:
            print(P.c("╔" + "═" * 78 + "╗", P.YELLOW))
            print(
                P.c("║", P.YELLOW)
                + P.c(" MERGERFS / CROSS-DEVICE BOUNDARY ALERT ", P.BOLD + P.YELLOW).center(87)
                + P.c("║", P.YELLOW)
            )
            print(P.c("╠" + "═" * 78 + "╣", P.YELLOW))
            for warn in report.warnings:
                wrapped_lines = self._wrap(warn, 74)
                for line in wrapped_lines:
                    print(P.c("║", P.YELLOW) + f"  {line}".ljust(78) + P.c("║", P.YELLOW))
            print(P.c("╚" + "═" * 78 + "╝", P.YELLOW))
            print()
        else:
            print(
                f" {P.c('✔ MergerFS Device Invariant:', P.GREEN)} "
                f"Single underlying device detected ({report.all_devs}). Hardlinks can form atomically."
            )
            print()

    def _print_summary_metrics(self) -> None:
        P = Palette
        over_inodes_count = len(self.auditor.over_linked_groups)
        over_paths_count = len(self.auditor.over_linked_files)
        ext_snap_note = (
            f" (incl. {self.auditor.normal_with_external_snapshots_count} with external snapshots)"
            if self.auditor.normal_with_external_snapshots_count > 0
            else ""
        )
        over_label = f"{over_inodes_count} unique inodes ({over_paths_count} paths)" if over_inodes_count > 0 else "0"

        print(P.c("┌── [1] AUDIT SUMMARY & METRICS " + "─" * 49, P.CYAN))
        print(f"│ Total Files Audited:      {P.c(str(self.auditor.total_scanned_files), P.BOLD)} ({format_bytes(self.auditor.total_scanned_bytes)})")
        print(f"│ Downloads Staging Files:  {self.auditor.downloads_file_count} ({format_bytes(self.auditor.downloads_total_bytes)})")
        if self.auditor.skipped_download_dirs:
            pats_str = ", ".join(f"'{p}'" for p in self.auditor.exclude_downloads)
            print(f"│ Excluded Download Dirs:   {P.c(str(len(self.auditor.skipped_download_dirs)), P.CYAN)} skipped ({pats_str})")
        print(f"│ Organized Library Files:  {self.auditor.library_file_count} ({format_bytes(self.auditor.library_total_bytes)})")
        print(f"│ Distinct Inode Keys:      {len(self.auditor.inode_map)}")
        print("│")
        print(f"│ Active Normal Hardlinks:  {P.c(str(self.auditor.normal_hardlinks_count), P.GREEN)} ({format_bytes(self.auditor.normal_hardlinks_bytes)}){ext_snap_note}")
        print(f"│ Orphan Staging Files:     {P.c(str(len(self.auditor.orphan_staging_files)), P.YELLOW if self.auditor.orphan_staging_files else P.GREEN)}")
        print(f"│ Ghost Links (Copies):     {P.c(str(len(self.auditor.ghost_links)), P.RED if self.auditor.ghost_links else P.GREEN)}")
        print(f"│ Over-Linked Inodes (>2):  {P.c(over_label, P.YELLOW if over_inodes_count else P.GREEN)}")
        print(f"│ Ghost Directories:        {P.c(str(len(self.auditor.ghost_directories)), P.YELLOW if self.auditor.ghost_directories else P.GREEN)}")
        print(f"│ TV Sequence Gaps:         {P.c(str(len(self.auditor.tv_gaps)), P.YELLOW if self.auditor.tv_gaps else P.GREEN)}")
        print(f"│ Music Album Gaps:         {P.c(str(len(self.auditor.music_gaps)), P.YELLOW if self.auditor.music_gaps else P.GREEN)}")
        print(f"│ Incomplete Datasets:      {P.c(str(len(self.auditor.dataset_inconsistencies)), P.YELLOW if self.auditor.dataset_inconsistencies else P.GREEN)}")
        print(P.c("└" + "─" * 79, P.CYAN))
        print()

    def _print_hardlink_discrepancies(self) -> None:
        P = Palette
        print(P.c("┌── [2] DOWNLOAD HARDLINK DISCREPANCIES " + "─" * 41, P.CYAN))

        # 2.1 Ghost Links
        print(f"│ {P.c('● Ghost Links (Library st_nlink == 1 matching Downloads name & size):', P.BOLD)} {len(self.auditor.ghost_links)}")
        if not self.auditor.ghost_links:
            print("│   (No ghost duplicate copies detected)")
        else:
            items_to_show = self.auditor.ghost_links if self.verbose else self.auditor.ghost_links[:5]
            for item in items_to_show:
                print(f"│   {P.c('✗ GHOST LINK:', P.RED)} {item.path} ({item.size_human})")
                if item.counterpart_paths:
                    print(f"│     ↳ Counterpart: {item.counterpart_paths[0]}")
                print(f"│     ↳ {P.c(item.details, P.DIM)}")
            if len(self.auditor.ghost_links) > len(items_to_show):
                print(f"│   ... and {len(self.auditor.ghost_links) - len(items_to_show)} more (use --verbose or --output-json)")

        print("│")

        # 2.2 Orphan Staging Files
        print(f"│ {P.c('● Orphan Staging Files (st_nlink == 1 in Downloads):', P.BOLD)} {len(self.auditor.orphan_staging_files)}")
        if not self.auditor.orphan_staging_files:
            print("│   (All downloads have active hardlinks or were imported)")
        else:
            items_to_show = self.auditor.orphan_staging_files if self.verbose else self.auditor.orphan_staging_files[:5]
            for item in items_to_show:
                print(f"│   {P.c('⚠ ORPHAN:', P.YELLOW)} {item.path} ({item.size_human})")
                print(f"│     ↳ Inode: {item.ino} | Dev: {item.dev} | {P.c(item.details, P.DIM)}")
            if len(self.auditor.orphan_staging_files) > len(items_to_show):
                print(f"│   ... and {len(self.auditor.orphan_staging_files) - len(items_to_show)} more")

        print("│")

        # 2.3 Over-linked files & Inference Engine
        over_inodes_count = len(self.auditor.over_linked_groups)
        over_paths_count = len(self.auditor.over_linked_files)
        inf = self.auditor.overlink_inference

        print(f"│ {P.c('● Over-Linked Inodes & Multi-Linked Staging:', P.BOLD)} {over_inodes_count} unique files ({over_paths_count} paths tracked)")
        if not self.auditor.over_linked_groups:
            print("│   (No over-linked files detected)")
        else:
            # Inference Box
            print("│")
            print("│   " + P.c("┌─ OVER-LINKING INFERENCE & ROOT-CAUSE DIAGNOSTICS " + "─" * 25, P.CYAN))

            # Physical Inode Sanity Check
            if inf and inf.inode_collision_detected:
                print("│   │ " + P.c("🚨 CRITICAL INODE COLLISION DETECTED!", P.BOLD + P.RED))
                print("│   │   Files of differing sizes report identical (st_dev, st_ino).")
                print("│   │   MergerFS is passing through raw inodes across branch disks without device isolation.")
                for c in inf.collision_details[:3]:
                    print(f"│   │   ↳ {c}")
            else:
                print("│   │ " + P.c("✔ Physical Inode Integrity:", P.GREEN) + " Verified sound.")
                print("│   │   All shared paths match exact byte size and attributes (zero MergerFS inode collisions).")

            if inf:
                print("│   │")
                print("│   │ " + P.c("── Inferred Root Causes ──", P.BOLD))
                cause_names = {
                    "cross_seeding": "Cross-Seeding Across Download Subdirectories",
                    "multi_library": "Multi-Library Destination Linking",
                    "external_snapshot": "External Snapshot / Backup Hardlinks",
                    "dedup_consolidation": "Deduplication Utility Consolidation",
                    "multi_link": "General Multi-Linked Files",
                }
                for cause_key, count in inf.cause_breakdown.items():
                    name = cause_names.get(cause_key, cause_key.replace("_", " ").title())
                    pct = (count / over_inodes_count * 100) if over_inodes_count else 0
                    print(f"│   │   ● {P.c(name + ':', P.BOLD)} {count} inodes ({pct:.1f}%)")

                if inf.top_cross_seed_folders:
                    print("│   │")
                    print("│   │   " + P.c("Top Cross-Seeded Source Folder Pairs:", P.BOLD))
                    for fpair in inf.top_cross_seed_folders:
                        print(f"│   │     ↳ '{fpair['folder_a']}' ↔ '{fpair['folder_b']}': {fpair['shared_inodes']} shared files")

                print("│   │")
                print("│   │ " + P.c("── Link Multiplicity & File Types ──", P.BOLD))
                hist_strs = [f"{k} links: {v}" for k, v in sorted(inf.link_histogram.items(), key=lambda x: int(x[0]))[:4]]
                print(f"│   │   ● Multiplicity: {', '.join(hist_strs)}")
                ext_strs = [f"{ext} ({cnt})" for ext, cnt in inf.extension_profile.items()]
                if ext_strs:
                    print(f"│   │   ● File Formats: {', '.join(ext_strs)}")

            print("│   " + P.c("└" + "─" * 72, P.CYAN))
            print("│")

            # Representative Samples (cleanly clamped to max 3 in non-verbose, 15 in verbose)
            max_samples = 15 if self.verbose else 3
            sample_groups = self.auditor.over_linked_groups[:max_samples]
            print("│   " + P.c(f"── Representative Over-Linked Inodes (Showing {len(sample_groups)} of {over_inodes_count}) ──", P.BOLD))
            for g in sample_groups:
                tag = f"[st_nlink={g.st_nlink} | DL: {g.downloads_count}, LIB: {g.libraries_count}, EXT: {g.external_count}]"
                print(f"│   {P.c(tag, P.MAGENTA)} {g.sample_name} ({g.size_human})")
                print(f"│     ↳ Inode: {g.ino} | Cause: {P.c(g.inferred_cause, P.BOLD)}")
                if g.downloads_paths:
                    print(f"│     ↳ Downloads ({len(g.downloads_paths)}):")
                    for p in g.downloads_paths[:2]:
                        print(f"│       • {p}")
                    if len(g.downloads_paths) > 2:
                        print(f"│       • ... +{len(g.downloads_paths) - 2} more download locations")
                if g.library_paths:
                    print(f"│     ↳ Libraries ({len(g.library_paths)}):")
                    for p in g.library_paths[:2]:
                        print(f"│       • {p}")
                    if len(g.library_paths) > 2:
                        print(f"│       • ... +{len(g.library_paths) - 2} more library locations")
                if g.external_count > 0:
                    print(f"│     ↳ External: {g.external_count} link(s) outside scanned directories (e.g. backup snapshots)")

            if over_inodes_count > len(sample_groups):
                print(f"│   ... and {over_inodes_count - len(sample_groups)} more unique inodes (see full breakdown with --output-json)")

        print(P.c("└" + "─" * 79, P.CYAN))
        print()

    def _print_ghost_directories(self) -> None:
        P = Palette
        print(P.c("┌── [3] SUSPECTED GHOST DIRECTORIES (LEFTOVER RESIDUE ONLY) " + "─" * 21, P.CYAN))
        print(f"│ Total Flagged Ghost Directories: {len(self.auditor.ghost_directories)}")

        if not self.auditor.ghost_directories:
            print("│   (No residue-only or empty orphan directories found)")
        else:
            items_to_show = self.auditor.ghost_directories if self.verbose else self.auditor.ghost_directories[:5]
            for gdir in items_to_show:
                tag = P.c("[EMPTY]", P.YELLOW) if gdir.is_empty else P.c("[RESIDUE ONLY]", P.RED)
                print(f"│   {tag} {gdir.path}")
                print(f"│     ↳ Residue: {gdir.residue_count} files ({gdir.total_residue_size_human}) | 0 payloads")
                if gdir.sample_residue_files:
                    samples_str = ", ".join(gdir.sample_residue_files[:3])
                    print(f"│     ↳ Samples: {P.c(samples_str, P.DIM)}")
            if len(self.auditor.ghost_directories) > len(items_to_show):
                print(f"│   ... and {len(self.auditor.ghost_directories) - len(items_to_show)} more")

        print(P.c("└" + "─" * 79, P.CYAN))
        print()

    def _print_structural_gaps(self) -> None:
        P = Palette
        print(P.c("┌── [4] GAPPED MEDIA & INCOMPLETE DATASETS " + "─" * 38, P.CYAN))

        # 4.1 TV Series
        print(f"│ {P.c('● TV Series Sequence Gaps & Orphan Seasons:', P.BOLD)} {len(self.auditor.tv_gaps)}")
        if not self.auditor.tv_gaps:
            print("│   (All series seasons are complete and continuous)")
        else:
            items_to_show = self.auditor.tv_gaps if self.verbose else self.auditor.tv_gaps[:5]
            for tv in items_to_show:
                tag = P.c("[ORPHAN SEASON]", P.MAGENTA) if tv.is_orphan_season else P.c("[SEQUENCE GAP]", P.YELLOW)
                print(f"│   {tag} {tv.series_name} (Season {tv.season})")
                print(f"│     ↳ Path: {tv.directory}")
                print(f"│     ↳ {P.c(tv.details, P.DIM)}")
            if len(self.auditor.tv_gaps) > len(items_to_show):
                print(f"│   ... and {len(self.auditor.tv_gaps) - len(items_to_show)} more")

        print("│")

        # 4.2 Music Albums
        print(f"│ {P.c('● Music Album Track Missing Indices:', P.BOLD)} {len(self.auditor.music_gaps)}")
        if not self.auditor.music_gaps:
            print("│   (All music albums contain complete track sequences)")
        else:
            items_to_show = self.auditor.music_gaps if self.verbose else self.auditor.music_gaps[:5]
            for album in items_to_show:
                print(f"│   {P.c('[MISSING TRACKS]', P.YELLOW)} {album.album_name}")
                print(f"│     ↳ Path: {album.directory}")
                print(f"│     ↳ {P.c(album.details, P.DIM)}")
            if len(self.auditor.music_gaps) > len(items_to_show):
                print(f"│   ... and {len(self.auditor.music_gaps) - len(items_to_show)} more")

        print("│")

        # 4.3 Datasets
        print(f"│ {P.c('● Machine Learning & Scientific Dataset Anomalies:', P.BOLD)} {len(self.auditor.dataset_inconsistencies)}")
        if not self.auditor.dataset_inconsistencies:
            print("│   (All candidate datasets possess valid splits and manifests)")
        else:
            items_to_show = (
                self.auditor.dataset_inconsistencies if self.verbose else self.auditor.dataset_inconsistencies[:5]
            )
            for ds in items_to_show:
                print(f"│   {P.c(f'[{ds.issue_type.upper()}]', P.RED)} {ds.dataset_name}")
                print(f"│     ↳ Path: {ds.directory}")
                print(f"│     ↳ {P.c(ds.details, P.DIM)}")
            if len(self.auditor.dataset_inconsistencies) > len(items_to_show):
                print(f"│   ... and {len(self.auditor.dataset_inconsistencies) - len(items_to_show)} more")

        print(P.c("└" + "─" * 79, P.CYAN))
        print()

    def _print_footer(self) -> None:
        P = Palette
        total_anomalies = (
            len(self.auditor.orphan_staging_files)
            + len(self.auditor.ghost_links)
            + len(self.auditor.over_linked_files)
            + len(self.auditor.ghost_directories)
            + len(self.auditor.tv_gaps)
            + len(self.auditor.music_gaps)
            + len(self.auditor.dataset_inconsistencies)
        )

        status_msg = (
            P.c(f"AUDIT COMPLETED: {total_anomalies} anomalies or structural discrepancies flagged.", P.BOLD + P.YELLOW)
            if total_anomalies > 0
            else P.c("AUDIT COMPLETED: Clean storage pool. All invariants satisfied.", P.BOLD + P.GREEN)
        )
        print(f" {status_msg}")
        if not self.verbose and total_anomalies > 0:
            print(f" {P.c('Tip:', P.CYAN)} Use {P.c('--verbose', P.BOLD)} for full itemized listings or {P.c('--output-json <path>', P.BOLD)} for automated processing.")
        print()

    @staticmethod
    def _wrap(text: str, width: int) -> List[str]:
        words = text.split()
        lines: List[str] = []
        curr: List[str] = []
        curr_len = 0
        for w in words:
            if curr_len + len(w) + (1 if curr else 0) > width:
                lines.append(" ".join(curr))
                curr = [w]
                curr_len = len(w)
            else:
                curr.append(w)
                curr_len += len(w) + (1 if len(curr) > 1 else 0)
        if curr:
            lines.append(" ".join(curr))
        return lines


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Audit a Linux storage pool (MergerFS / underlying branch disks) "
            "for hardlink anomalies, ghost directory residue, and gapped media/datasets. "
            "Strictly read-only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-d",
        "--downloads",
        "--downloads-dir",
        dest="downloads",
        required=True,
        help="Path to staging / torrent download tree.",
    )
    parser.add_argument(
        "-l",
        "--libraries",
        "--library-dirs",
        dest="libraries",
        required=True,
        nargs="+",
        help="One or more paths to organized media / dataset library trees.",
    )
    parser.add_argument(
        "-x",
        "--exclude-downloads",
        "--exclude-download-dirs",
        "--ignore-downloads",
        dest="exclude_downloads",
        action="extend",
        nargs="+",
        default=[],
        help=(
            "Subdirectories or glob patterns within the staging/downloads directory to "
            "blacklist/exclude (e.g. 'incomplete', 'temp', 'torrents/temp', '*single*'). "
            "Prunes matching directories from traversal."
        ),
    )
    parser.add_argument(
        "-o",
        "--output-json",
        dest="output_json",
        help="Optional path to write full structured diagnostic report in a single JSON file.",
    )
    parser.add_argument(
        "--output-dir",
        "--export-dir",
        "--split-output-dir",
        dest="output_dir",
        help="Directory path to export separate, dedicated report files for each anomaly flag category (.json and .txt).",
    )
    parser.add_argument(
        "--split-reports",
        "--separate-reports",
        dest="split_reports",
        action="store_true",
        help="Generate separate output files for each type of flag (uses --output-dir if set, or defaults to './audit_reports').",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Toggle detailed item-by-item breakdown instead of truncated sample view.",
    )
    parser.add_argument(
        "--payload-threshold-mb",
        dest="payload_threshold_mb",
        type=int,
        default=100,
        help="Threshold in MB for primary payload classification in ghost directories (default: 100).",
    )
    parser.add_argument(
        "--no-color",
        dest="no_color",
        action="store_true",
        help="Disable ANSI color formatting.",
    )

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    Palette.setup(force_no_color=args.no_color)

    # Validate paths exist
    if not os.path.isdir(args.downloads):
        print(f"Error: Downloads path '{args.downloads}' is not an accessible directory.", file=sys.stderr)
        return 2

    for lib in args.libraries:
        if not os.path.isdir(lib):
            print(f"Error: Library path '{lib}' is not an accessible directory.", file=sys.stderr)
            return 2

    payload_threshold_bytes = max(1, args.payload_threshold_mb) * 1024 * 1024

    auditor = StorageAuditor(
        downloads_dir=args.downloads,
        library_dirs=args.libraries,
        exclude_downloads=args.exclude_downloads,
        payload_threshold_bytes=payload_threshold_bytes,
        verbose=args.verbose,
    )

    try:
        auditor.run()
    except Exception as e:
        print(f"Fatal error during storage audit: {e}", file=sys.stderr)
        return 1

    # Terminal report
    reporter = TerminalReporter(auditor, verbose=args.verbose)
    reporter.render()

    # Optional JSON export
    if args.output_json:
        report_data = auditor.build_report_dict()
        try:
            out_path = Path(args.output_json).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
            print(f" {Palette.c('✔ Consolidated JSON Report Exported:', Palette.GREEN)} {out_path}")
            print()
        except OSError as e:
            print(f"Error writing JSON report to '{args.output_json}': {e}", file=sys.stderr)
            return 1

    # Optional separate report files per flag category
    export_dir = None
    if args.output_dir:
        export_dir = args.output_dir
    elif args.split_reports:
        if args.output_json:
            export_dir = str(Path(args.output_json).parent / (Path(args.output_json).stem + "_by_flag"))
        else:
            export_dir = "audit_reports"

    if export_dir:
        try:
            manifest = auditor.export_separate_reports(export_dir)
            P = Palette
            print(f" {P.c('✔ Separate Reports Exported by Flag Category:', P.GREEN)} {manifest['output_directory']}")
            print(f"   ├── {P.c('audit_summary.json & .txt', P.BOLD)}")
            print(f"   ├── {P.c('orphaned_staging_files.json & .txt', P.BOLD)} ({manifest['files']['orphaned_staging_files']['count']} files)")
            print(f"   ├── {P.c('ghost_links.json & .txt', P.BOLD)} ({manifest['files']['ghost_links']['count']} files)")
            print(f"   ├── {P.c('over_linked_files.json & .txt', P.BOLD)} ({manifest['files']['over_linked_files']['total_paths']} paths across {manifest['files']['over_linked_files']['unique_inodes']} unique inodes)")
            print(f"   ├── {P.c('ghost_directories.json & .txt', P.BOLD)} ({manifest['files']['ghost_directories']['count']} directories)")
            print(f"   ├── {P.c('tv_sequence_gaps.json & .txt', P.BOLD)} ({manifest['files']['tv_sequence_gaps']['count']} seasons with gaps)")
            print(f"   ├── {P.c('music_album_gaps.json & .txt', P.BOLD)} ({manifest['files']['music_album_gaps']['count']} albums with gaps)")
            print(f"   └── {P.c('dataset_inconsistencies.json & .txt', P.BOLD)} ({manifest['files']['dataset_inconsistencies']['count']} inconsistencies)")
            print()
        except OSError as e:
            print(f"Error exporting separate reports to '{export_dir}': {e}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
