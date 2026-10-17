#!/usr/bin/env python3
"""
test_audit_storage.py - Exhaustive verification test suite for audit_storage.py
Tests hardlinks, ghost links, ghost directories, TV gaps, music gaps, datasets,
cross-device warnings, JSON outputs, and read-only invariants.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


def hash_tree(root_dir: str) -> dict[str, str]:
    """Computes SHA256 hashes of all regular files in a directory tree."""
    hashes = {}
    for root, _, files in os.walk(root_dir):
        for f in sorted(files):
            p = os.path.join(root, f)
            with open(p, "rb") as fh:
                hashes[p] = hashlib.sha256(fh.read()).hexdigest()
    return hashes


class TestAuditStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.script_path = str(Path(__file__).parent / "audit_storage.py")

        # Create test directory trees
        self.downloads_dir = self.root / "downloads"
        self.downloads_dir.mkdir(parents=True)

        self.tv_dir = self.root / "library_tv"
        self.movies_dir = self.root / "library_movies"
        self.music_dir = self.root / "library_music"
        self.datasets_dir = self.root / "library_datasets"

        for d in [self.tv_dir, self.movies_dir, self.music_dir, self.datasets_dir]:
            d.mkdir(parents=True)

        # ----------------------------------------------------------------------
        # 1. Normal Hardlink: active_file.mkv (st_nlink == 2)
        # ----------------------------------------------------------------------
        dl_active = self.downloads_dir / "active_file.mkv"
        dl_active.write_bytes(b"A" * 1024 * 1024 * 5)  # 5MB payload

        tv_show_s1 = self.tv_dir / "Breaking Good" / "Season 01"
        tv_show_s1.mkdir(parents=True)
        lib_active = tv_show_s1 / "Breaking Good - S01E01.mkv"
        os.link(dl_active, lib_active)  # Hardlink created!

        # ----------------------------------------------------------------------
        # 2. Orphan Staging: orphan_file.mkv (st_nlink == 1 in downloads)
        # ----------------------------------------------------------------------
        dl_orphan = self.downloads_dir / "orphan_file.mkv"
        dl_orphan.write_bytes(b"O" * 1024 * 1024 * 8)

        # ----------------------------------------------------------------------
        # 3. Ghost Link: copy instead of hardlink
        # ----------------------------------------------------------------------
        dl_ghost = self.downloads_dir / "Interstellar.2014.1080p.mkv"
        dl_ghost.write_bytes(b"G" * 1024 * 1024 * 12)

        movie_folder = self.movies_dir / "Interstellar (2014)"
        movie_folder.mkdir(parents=True)
        lib_ghost = movie_folder / "Interstellar.2014.1080p.mkv"
        # Separate copy with identical name and size (st_nlink == 1 on both)
        lib_ghost.write_bytes(b"G" * 1024 * 1024 * 12)

        # ----------------------------------------------------------------------
        # 4. Over-Linked File: (st_nlink > 2)
        # ----------------------------------------------------------------------
        dl_over = self.downloads_dir / "sample_overlinked.mkv"
        dl_over.write_bytes(b"L" * 1024 * 1024 * 2)
        lib_over1 = self.movies_dir / "Copy1.mkv"
        lib_over2 = self.movies_dir / "Copy2.mkv"
        os.link(dl_over, lib_over1)
        os.link(dl_over, lib_over2)  # Now st_nlink == 3

        # ----------------------------------------------------------------------
        # 5. Suspected Ghost Directory (Residue Only)
        # ----------------------------------------------------------------------
        ghost_dir = self.movies_dir / "Deleted Movie (2000)"
        ghost_dir.mkdir(parents=True)
        (ghost_dir / "movie.nfo").write_text("Movie metadata info")
        (ghost_dir / "english.srt").write_text("1\n00:00:01,000 --> 00:00:04,000\nHello")
        (ghost_dir / "poster.jpg").write_bytes(b"\xFF\xD8\xFF\xE0" + b"\x00" * 200)

        # ----------------------------------------------------------------------
        # 6. TV Series Sequence Gap: ShowA has S01E01, S01E02, S01E04 (missing E03)
        # ----------------------------------------------------------------------
        (tv_show_s1 / "Breaking Good - S01E02.mkv").write_bytes(b"V" * 1024 * 1024 * 2)
        (tv_show_s1 / "Breaking Good - S01E04.mkv").write_bytes(b"V" * 1024 * 1024 * 2)

        # ----------------------------------------------------------------------
        # 7. TV Series Orphan Season: ShowB Season 2 has only S02E01
        # ----------------------------------------------------------------------
        tv_show_b_s2 = self.tv_dir / "Show B" / "Season 02"
        tv_show_b_s2.mkdir(parents=True)
        (tv_show_b_s2 / "Show B - S02E01.mkv").write_bytes(b"V" * 1024 * 1024 * 2)

        # ----------------------------------------------------------------------
        # 8. Music Album Missing Track: AlbumX has tracks 01, 02, 04 (missing 03)
        # ----------------------------------------------------------------------
        album_dir = self.music_dir / "Artist" / "AlbumX"
        album_dir.mkdir(parents=True)
        (album_dir / "01 - Track One.flac").write_bytes(b"F" * 1024 * 1024 * 2)
        (album_dir / "02 - Track Two.flac").write_bytes(b"F" * 1024 * 1024 * 2)
        (album_dir / "04 - Track Four.flac").write_bytes(b"F" * 1024 * 1024 * 2)

        # ----------------------------------------------------------------------
        # 9. Datasets:
        # 9a. CV Dataset missing labels: has images/ but no labels/
        # ----------------------------------------------------------------------
        ds_cv = self.datasets_dir / "VisionDataset"
        (ds_cv / "images").mkdir(parents=True)
        (ds_cv / "images" / "001.jpg").write_bytes(b"\x00" * 100)

        # 9b. NLP Dataset train only: has train/ but no val/ or test/
        ds_nlp = self.datasets_dir / "TextCorpus"
        (ds_nlp / "train").mkdir(parents=True)
        (ds_nlp / "train" / "train.csv").write_text("col1,col2\n1,2")

        # 9c. Dataset missing manifest: has train/ and val/ but no dataset.json/classes.txt
        ds_manifest = self.datasets_dir / "StructuredData"
        (ds_manifest / "train").mkdir(parents=True)
        (ds_manifest / "train" / "sample.txt").write_text("train")
        (ds_manifest / "val").mkdir(parents=True)
        (ds_manifest / "val" / "sample.txt").write_text("val")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_full_audit_workflow(self):
        """Runs audit_storage.py and verifies all diagnostic sections & counts."""
        json_output = self.root / "audit_report.json"

        # Record file states before execution to verify read-only behavior
        pre_hashes = hash_tree(str(self.root))

        cmd = [
            sys.executable,
            self.script_path,
            "--downloads", str(self.downloads_dir),
            "--libraries", str(self.tv_dir), str(self.movies_dir), str(self.music_dir), str(self.datasets_dir),
            "--output-json", str(json_output),
            "--verbose",
            "--no-color",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"Script failed with stderr: {result.stderr}")

        stdout = result.stdout

        # Verify terminal output sections
        self.assertIn("STORAGE POOL & HARDLINK INVARIANT AUDIT REPORT", stdout)
        self.assertIn("[1] AUDIT SUMMARY & METRICS", stdout)
        self.assertIn("[2] DOWNLOAD HARDLINK DISCREPANCIES", stdout)
        self.assertIn("[3] SUSPECTED GHOST DIRECTORIES", stdout)
        self.assertIn("[4] GAPPED MEDIA & INCOMPLETE DATASETS", stdout)

        # Verify JSON report exists and is valid
        self.assertTrue(json_output.exists(), "JSON output was not created")
        with open(json_output, "r", encoding="utf-8") as f:
            data = json.load(f)

        summary_counts = data["summary"]["counts"]

        # Invariant 1: Normal active hardlinks (active_file.mkv)
        self.assertGreaterEqual(summary_counts["normal_active_hardlinks"], 1)

        # Invariant 2: Orphan staging file (orphan_file.mkv)
        self.assertGreaterEqual(summary_counts["orphaned_staging_files"], 1)
        orphan_names = [o["name"] for o in data["download_hardlink_discrepancies"]["orphaned_staging_files"]]
        self.assertIn("orphan_file.mkv", orphan_names)

        # Invariant 3: Ghost Link (Interstellar.2014.1080p.mkv)
        self.assertEqual(summary_counts["ghost_links"], 1)
        ghost_names = [g["name"] for g in data["download_hardlink_discrepancies"]["ghost_links"]]
        self.assertIn("Interstellar.2014.1080p.mkv", ghost_names)

        # Invariant 4: Over-linked file (sample_overlinked.mkv with 3 links)
        self.assertGreaterEqual(summary_counts["over_linked_files"], 1)
        over_names = [ov["name"] for ov in data["download_hardlink_discrepancies"]["over_linked_files"]]
        self.assertIn("sample_overlinked.mkv", over_names)

        # Invariant 5: Ghost directory (Deleted Movie (2000))
        self.assertGreaterEqual(summary_counts["ghost_directories"], 1)
        ghost_dir_paths = [gd["path"] for gd in data["suspected_ghost_directories"]]
        self.assertTrue(any("Deleted Movie (2000)" in p for p in ghost_dir_paths))

        # Invariant 6: TV series sequence gap (Breaking Good Season 1 missing E03)
        tv_gaps = data["structural_media_and_dataset_gaps"]["tv_series_gaps"]
        gap_series = [t for t in tv_gaps if not t["is_orphan_season"]]
        self.assertEqual(len(gap_series), 1)
        self.assertEqual(gap_series[0]["series_name"], "Breaking Good")
        self.assertEqual(gap_series[0]["season"], 1)
        self.assertIn(3, gap_series[0]["missing_episodes"])

        # Invariant 7: TV series orphan season (Show B Season 2 only 1 episode)
        orphan_seasons = [t for t in tv_gaps if t["is_orphan_season"]]
        self.assertEqual(len(orphan_seasons), 1)
        self.assertEqual(orphan_seasons[0]["series_name"], "Show B")
        self.assertEqual(orphan_seasons[0]["season"], 2)

        # Invariant 8: Music album track gap (AlbumX missing track 3)
        music_gaps = data["structural_media_and_dataset_gaps"]["music_album_gaps"]
        self.assertEqual(len(music_gaps), 1)
        self.assertEqual(music_gaps[0]["album_name"], "AlbumX")
        self.assertIn(3, music_gaps[0]["missing_tracks"])

        # Invariant 9: Datasets
        ds_gaps = data["structural_media_and_dataset_gaps"]["dataset_inconsistencies"]
        issue_types = {d["issue_type"] for d in ds_gaps}
        self.assertIn("missing_labels", issue_types)
        self.assertIn("train_only", issue_types)
        self.assertIn("missing_manifest", issue_types)

        # Strict Verification: Read-Only Safety Check
        # Verify no files were modified, moved, or deleted
        post_hashes = hash_tree(str(self.root))
        # Remove audit_report.json from post_hashes before comparison
        post_hashes.pop(str(json_output), None)
        self.assertEqual(pre_hashes, post_hashes, "Storage audit violated read-only constraint!")

    def test_missing_directory_error_handling(self):
        """Tests that invalid directories return exit code 2 and a clean message."""
        cmd = [
            sys.executable,
            self.script_path,
            "--downloads", "/non/existent/path/downloads",
            "--libraries", str(self.tv_dir),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not an accessible directory", result.stderr)

    def test_mergerfs_cross_device_detection(self):
        """Tests that differing st_dev values trigger cross-device warnings and alerts."""
        from audit_storage import StorageAuditor

        auditor = StorageAuditor(
            downloads_dir=str(self.downloads_dir),
            library_dirs=[str(self.tv_dir)],
        )
        # Simulate different device IDs
        auditor.download_devs = {2049}
        auditor.library_devs = {2050}

        report = auditor.get_mergerfs_report()
        self.assertTrue(report.cross_device_detected)
        self.assertEqual(len(report.warnings), 4)
        self.assertIn("EXDEV", report.warnings[1])

    def test_symlink_safety(self):
        """Ensures that symlinks are not followed into loops and follow_symlinks=False is enforced."""
        symlink_loop = self.downloads_dir / "loop_link"
        try:
            symlink_loop.symlink_to(self.downloads_dir)
        except OSError:
            pass  # If OS doesn't allow self-loop symlinks

        symlink_file = self.downloads_dir / "link_to_orphan.mkv"
        try:
            symlink_file.symlink_to(self.downloads_dir / "orphan_file.mkv")
        except OSError:
            pass

        cmd = [
            sys.executable,
            self.script_path,
            "--downloads", str(self.downloads_dir),
            "--libraries", str(self.tv_dir),
            "--no-color",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)

    def test_nested_subdirectories_in_downloads(self):
        """Tests that nested subdirectories in downloads are fully traversed and hardlinks/ghost links resolved."""
        # 1. Nested download folder: downloads/torrents/seeding/ShowX
        nested_dl_folder = self.downloads_dir / "torrents" / "seeding" / "ShowX.S03.1080p"
        nested_dl_folder.mkdir(parents=True)
        nested_file = nested_dl_folder / "showx.s03e01.mkv"
        nested_file.write_bytes(b"N" * 1024 * 1024 * 3)

        # Hardlinked into library
        lib_show = self.tv_dir / "Show X" / "Season 03"
        lib_show.mkdir(parents=True)
        lib_ep = lib_show / "Show X - S03E01.mkv"
        os.link(nested_file, lib_ep)

        # 2. Nested download folder with renamed copy (Ghost Link):
        # Staging: downloads/usenet/completed/FilmY/sparks-filmy.mkv (11MB)
        # Library: movies/Film Y/Film Y (2024).mkv (11MB, separate inode)
        usenet_folder = self.downloads_dir / "usenet" / "completed" / "FilmY"
        usenet_folder.mkdir(parents=True)
        usenet_file = usenet_folder / "sparks-filmy.mkv"
        usenet_file.write_bytes(b"Y" * 1024 * 1024 * 11)

        lib_filmy_folder = self.movies_dir / "Film Y (2024)"
        lib_filmy_folder.mkdir(parents=True)
        lib_filmy_file = lib_filmy_folder / "Film Y (2024).mkv"
        lib_filmy_file.write_bytes(b"Y" * 1024 * 1024 * 11)

        from audit_storage import StorageAuditor
        auditor = StorageAuditor(
            downloads_dir=str(self.downloads_dir),
            library_dirs=[str(self.tv_dir), str(self.movies_dir)],
        )
        auditor.run()

        # Verify the nested hardlink was counted
        active_paths = [rec.path for pairs in auditor.inode_map.values() for rec in pairs["downloads"] if rec.nlink == 2]
        self.assertIn(str(nested_file), active_paths)

        # Verify the renamed copy in nested folder was detected as a Ghost Link
        ghost_names = [g.name for g in auditor.ghost_links]
        self.assertIn("Film Y (2024).mkv", ghost_names)

    def test_overlink_inference_and_cross_seeding(self):
        """Tests that cross-seeded files across download subdirectories are grouped and inferred accurately."""
        # Create cross-seeded files across tracker_a and tracker_b
        tracker_a = self.downloads_dir / "torrents" / "tracker_a" / "Album"
        tracker_b = self.downloads_dir / "torrents" / "tracker_b" / "Album"
        tracker_a.mkdir(parents=True)
        tracker_b.mkdir(parents=True)

        file_a = tracker_a / "01.flac"
        file_b = tracker_b / "01.flac"
        file_a.write_bytes(b"M" * 1024 * 1024 * 4)
        os.link(file_a, file_b)  # Hardlinked in downloads (st_nlink == 2)

        # Linked into library (st_nlink becomes 3)
        music_lib = self.music_dir / "ArtistZ" / "Album"
        music_lib.mkdir(parents=True)
        file_lib = music_lib / "01.flac"
        os.link(file_a, file_lib)

        from audit_storage import StorageAuditor
        auditor = StorageAuditor(
            downloads_dir=str(self.downloads_dir),
            library_dirs=[str(self.music_dir)],
        )
        auditor.run()

        # Find the group for this file
        group = next((g for g in auditor.over_linked_groups if g.sample_name == "01.flac"), None)
        self.assertIsNotNone(group)
        self.assertEqual(group.st_nlink, 3)
        self.assertEqual(group.downloads_count, 2)
        self.assertEqual(group.libraries_count, 1)
        self.assertEqual(group.external_count, 0)
        self.assertEqual(group.inferred_cause, "cross_seeding")

        # Verify inference report contains the cross-seed folders
        inf = auditor.overlink_inference
        self.assertIsNotNone(inf)
        self.assertTrue(inf.physical_sanity_verified)
        self.assertFalse(inf.inode_collision_detected)
        self.assertIn("cross_seeding", inf.cause_breakdown)

    def test_inode_collision_detection(self):
        """Tests that files with different sizes sharing the same (dev, ino) trigger the collision alert."""
        from audit_storage import FileRecord, StorageAuditor
        auditor = StorageAuditor(
            downloads_dir=str(self.downloads_dir),
            library_dirs=[str(self.music_dir)],
        )
        # Mock an inode collision: same (dev, ino) but different sizes
        auditor.inode_map[(100, 500)]["downloads"].append(
            FileRecord(path="/dl/file1.mkv", name="file1.mkv", dev=100, ino=500, nlink=2, size=1000, is_download=True)
        )
        auditor.inode_map[(100, 500)]["libraries"].append(
            FileRecord(path="/lib/file2.mkv", name="file2.mkv", dev=100, ino=500, nlink=2, size=2000, is_download=False)
        )
        auditor._analyze_hardlink_invariants()
        self.assertTrue(auditor.inode_collision_detected)
        self.assertGreaterEqual(len(auditor.inode_collisions), 1)


if __name__ == "__main__":
    unittest.main()

