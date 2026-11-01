"""Tests for update_manifest.py: golden manifest and hostile inputs."""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import update_manifest as um

GOLDEN = HERE / "testdata" / "golden-manifest.json"
BASE = "https://example.invalid/releases/download/v1.2.3"
X86 = "x86_64-unknown-linux-gnu"
ARM = "aarch64-unknown-linux-gnu"
X86_BYTES = b"x86 archive bytes\n"
ARM_BYTES = b"arm archive bytes, a little longer\n"


class Fixture:
    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        return self

    def __exit__(self, *exc):
        self.tmp.cleanup()

    def archive(self, name, data):
        path = self.dir / name
        path.write_bytes(data)
        return path


def build(entries, **over):
    args = dict(version="1.2.3", seq=7, min_protocol=1, base_url=BASE, entries=entries)
    args.update(over)
    return um.build_manifest(**args)


class Golden(unittest.TestCase):
    def test_matches_golden_file(self):
        with Fixture() as fx:
            x86 = fx.archive("fleetd-x86_64-unknown-linux-musl.tar.gz", X86_BYTES)
            arm = fx.archive("fleetd-aarch64-unknown-linux-musl.tar.gz", ARM_BYTES)
            text = build([(ARM, arm), (X86, x86)])
        self.assertEqual(text, GOLDEN.read_text())

    def test_output_parses_in_fleetd_shape(self):
        doc = json.loads(GOLDEN.read_text())
        self.assertEqual(list(doc), ["version", "min_protocol", "seq", "targets"])
        for target in doc["targets"].values():
            self.assertEqual(sorted(target), ["sha256", "size", "url"])
            self.assertRegex(target["sha256"], r"^[0-9a-f]{64}$")

    def test_cli_writes_the_file(self):
        with Fixture() as fx:
            x86 = fx.archive("fleetd-x86_64-unknown-linux-musl.tar.gz", X86_BYTES)
            arm = fx.archive("fleetd-aarch64-unknown-linux-musl.tar.gz", ARM_BYTES)
            out = fx.dir / "manifest.json"
            run = subprocess.run(
                [
                    sys.executable,
                    str(HERE / "update_manifest.py"),
                    "--version", "1.2.3",
                    "--seq", "7",
                    "--base-url", BASE,
                    "--target", f"{X86}={x86}",
                    "--target", f"{ARM}={arm}",
                    "--out", str(out),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(out.read_text(), GOLDEN.read_text())

    def test_cli_refuses_bad_input_with_nonzero_exit(self):
        with Fixture() as fx:
            out = fx.dir / "manifest.json"
            run = subprocess.run(
                [
                    sys.executable,
                    str(HERE / "update_manifest.py"),
                    "--version", "1.2.3",
                    "--seq", "7",
                    "--base-url", BASE,
                    "--target", f"{X86}={fx.dir / 'missing.tar.gz'}",
                    "--out", str(out),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse(out.exists())


class Hostile(unittest.TestCase):
    def test_archive_names(self):
        names = [
            "fleetd\nx.tar.gz",
            "fleetd\r\nx.tar.gz",
            'fleetd"x.tar.gz',
            "fleetd'x.tar.gz",
            "fleetd x.tar.gz",
            "fleetd\\x.tar.gz",
            "fleetd@x.tar.gz",
            "fleetd x.tar.gz",
            "fléetd.tar.gz",
            "fleetd#x.tar.gz",
            "fleetd?x.tar.gz",
            "fleetd%2fx.tar.gz",
            ".hidden",
            "a" * 3000 + ".tar.gz",
        ]
        for name in names:
            with self.subTest(name=name):
                with Fixture() as fx:
                    path = fx.dir / name
                    try:
                        path.write_bytes(b"x")
                    except OSError:
                        pass
                    with self.assertRaises(um.ManifestError):
                        build([(X86, path)])

    def test_target_names(self):
        bad = [
            "",
            "X86_64",
            "x86 64",
            "x86\n64",
            "x86/64",
            "x86\\64",
            "x86\"64",
            "t" * 65,
            "é",
            "x86_64 ",
        ]
        for target in bad:
            with self.subTest(target=target):
                with Fixture() as fx:
                    path = fx.archive("fleetd.tar.gz", b"x")
                    with self.assertRaises(um.ManifestError):
                        build([(target, path)])

    def test_missing_archive(self):
        with Fixture() as fx:
            with self.assertRaises(um.ManifestError):
                build([(X86, fx.dir / "absent.tar.gz")])

    def test_directory_instead_of_archive(self):
        with Fixture() as fx:
            sub = fx.dir / "fleetd.tar.gz"
            sub.mkdir()
            with self.assertRaises(um.ManifestError):
                build([(X86, sub)])

    def test_empty_archive(self):
        with Fixture() as fx:
            path = fx.archive("fleetd.tar.gz", b"")
            with self.assertRaises(um.ManifestError):
                build([(X86, path)])

    def test_oversize_archive_by_one_byte(self):
        with Fixture() as fx:
            path = fx.archive("fleetd.tar.gz", b"x" * 11)
            with self.assertRaises(um.ManifestError):
                um.build_manifest(
                    version="1.2.3",
                    seq=1,
                    min_protocol=1,
                    base_url=BASE,
                    entries=[(X86, path)],
                    max_archive_bytes=10,
                )
            ok = um.build_manifest(
                version="1.2.3",
                seq=1,
                min_protocol=1,
                base_url=BASE,
                entries=[(X86, path)],
                max_archive_bytes=11,
            )
            self.assertIn('"size": 11', ok)

    def test_no_targets(self):
        with self.assertRaises(um.ManifestError):
            build([])

    def test_too_many_targets(self):
        with Fixture() as fx:
            path = fx.archive("fleetd.tar.gz", b"x")
            entries = [(f"t{i}", path) for i in range(um.MAX_TARGETS + 1)]
            with self.assertRaises(um.ManifestError):
                build(entries)
            build(entries[: um.MAX_TARGETS])

    def test_duplicate_target(self):
        with Fixture() as fx:
            path = fx.archive("fleetd.tar.gz", b"x")
            with self.assertRaises(um.ManifestError):
                build([(X86, path), (X86, path)])

    def test_versions(self):
        with Fixture() as fx:
            path = fx.archive("fleetd.tar.gz", b"x")
            for version in ["", "1.2", "v1.2.3", "1.2.3\n", "1.2.3 ", "01.2.3", "1.2.3+\"", "1.2.3+build.5", "1.2.3-rc.1+b", "x"]:
                with self.subTest(version=version):
                    with self.assertRaises(um.ManifestError):
                        build([(X86, path)], version=version)
            build([(X86, path)], version="1.2.3-rc.1")

    def test_seq(self):
        with Fixture() as fx:
            path = fx.archive("fleetd.tar.gz", b"x")
            for seq in [0, -1, 2**64]:
                with self.subTest(seq=seq):
                    with self.assertRaises(um.ManifestError):
                        build([(X86, path)], seq=seq)
            build([(X86, path)], seq=2**64 - 1)

    def test_base_urls(self):
        with Fixture() as fx:
            path = fx.archive("fleetd.tar.gz", b"x")
            bad = [
                "http://example.invalid/a",
                "https://",
                "",
                "https://user@example.invalid/a",
                "https://example.invalid/a\\b",
                "https://example.invalid/a b",
                "https://example.invalid/a\nb",
                "https://example.invalid/ ",
                "ftp://example.invalid/a",
                "https://example.invalid/a#b",
                "https://example.invalid/a?b",
                "https://example.invalid/a%23b",
                "https://example.invalid/" + "a" * 2100,
            ]
            for url in bad:
                with self.subTest(url=url):
                    with self.assertRaises(um.ManifestError):
                        build([(X86, path)], base_url=url)

    def test_base_url_trailing_slash(self):
        with Fixture() as fx:
            path = fx.archive("fleetd.tar.gz", b"x")
            with self.assertRaises(um.ManifestError):
                build([(X86, path)], base_url=BASE + "/")

    def test_url_length_boundary(self):
        with Fixture() as fx:
            path = fx.archive("fleetd.tar.gz", b"x")
            prefix = "https://e.invalid/"
            room = um.MAX_URL_BYTES - len(prefix) - len("/fleetd.tar.gz")
            build([(X86, path)], base_url=prefix + "a" * room)
            with self.assertRaises(um.ManifestError):
                build([(X86, path)], base_url=prefix + "a" * (room + 1))

    def test_manifest_cap(self):
        with Fixture() as fx:
            path = fx.archive("fleetd.tar.gz", b"x")
            with self.assertRaises(um.ManifestError):
                build([(X86, path)], max_manifest_bytes=100)

    def test_cli_refuses_a_target_without_equals(self):
        run = subprocess.run(
            [
                sys.executable,
                str(HERE / "update_manifest.py"),
                "--version", "1.2.3",
                "--seq", "1",
                "--base-url", BASE,
                "--target", "nothing",
                "--out", os.devnull,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(run.returncode, 0)


if __name__ == "__main__":
    unittest.main()
