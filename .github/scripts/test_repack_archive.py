"""Tests for repack_archive.py: the archive shape fleetd's unpacker requires."""

import gzip
import io
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import repack_archive as ra

SCRIPT = HERE / "repack_archive.py"
BIN = b"\x7fELF fixture binary\n" * 50


def raw_blocks(gz_bytes):
    data = gzip.decompress(gz_bytes)
    return [data[i : i + 512] for i in range(0, len(data), 512)]


def nested(path, mode, entries):
    with tarfile.open(path, mode) as tar:
        for name, kind, data, link in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.mode = 0o755
            info.linkname = link
            if kind == tarfile.REGTYPE:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            else:
                tar.addfile(info)


class Fixture:
    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        return self

    def __exit__(self, *exc):
        self.tmp.cleanup()


class Shape(unittest.TestCase):
    def check_output(self, out):
        data = out.read_bytes()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            members = tar.getmembers()
        self.assertEqual([m.name for m in members], ["fleetd"])
        member = members[0]
        self.assertTrue(member.isreg())
        self.assertEqual(member.mode, 0o755)
        self.assertEqual(member.mtime, 0)
        self.assertEqual((member.uid, member.gid), (0, 0))
        self.assertEqual(member.size, len(BIN))
        blocks = raw_blocks(data)
        header = blocks[0]
        self.assertEqual(header[257:263], b"ustar\x00")
        self.assertEqual(header[156:157], b"0")
        nonzero = [b for b in blocks if any(b)]
        self.assertEqual(len(nonzero), 1 + len(BIN) // 512 + 1)
        self.assertEqual(gzip.decompress(data)[512 : 512 + len(BIN)], BIN)

    def test_from_a_binary(self):
        with Fixture() as fx:
            binary = fx.dir / "bin"
            binary.write_bytes(BIN)
            out = fx.dir / "out.tar.gz"
            ra.repack_binary(binary, out)
            self.check_output(out)

    def test_from_nested_gz_and_xz_dist_archives(self):
        for mode, name in [("w:gz", "d.tar.gz"), ("w:xz", "d.tar.xz")]:
            with Fixture() as fx:
                src = fx.dir / name
                nested(
                    src,
                    mode,
                    [
                        ("fleetd-x/", tarfile.DIRTYPE, b"", ""),
                        ("fleetd-x/fleetd", tarfile.REGTYPE, BIN, ""),
                        ("fleetd-x/README.md", tarfile.REGTYPE, b"hi", ""),
                    ],
                )
                out = fx.dir / "out.tar.gz"
                ra.repack_archive(src, out)
                self.check_output(out)

    def test_output_is_deterministic(self):
        with Fixture() as fx:
            binary = fx.dir / "bin"
            binary.write_bytes(BIN)
            a, b = fx.dir / "a.tar.gz", fx.dir / "b.tar.gz"
            ra.repack_binary(binary, a)
            ra.repack_binary(binary, b)
            self.assertEqual(a.read_bytes(), b.read_bytes())

    def test_pax_is_never_written_for_a_long_name_source(self):
        with Fixture() as fx:
            src = fx.dir / "d.tar.gz"
            deep = "a" * 120 + "/fleetd"
            nested(src, "w:gz", [(deep, tarfile.REGTYPE, BIN, "")])
            out = fx.dir / "out.tar.gz"
            ra.repack_archive(src, out)
            self.check_output(out)

    def test_cli(self):
        with Fixture() as fx:
            binary = fx.dir / "bin"
            binary.write_bytes(BIN)
            out = fx.dir / "out.tar.gz"
            run = subprocess.run(
                [sys.executable, str(SCRIPT), "--binary", str(binary), "--out", str(out)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.check_output(out)


class Hostile(unittest.TestCase):
    def refuses(self, entries, mode="w:gz"):
        with Fixture() as fx:
            src = fx.dir / "d.tar.gz"
            nested(src, mode, entries)
            out = fx.dir / "out.tar.gz"
            with self.assertRaises(ra.RepackError):
                ra.repack_archive(src, out)
            self.assertFalse(out.exists())

    def test_no_fleetd(self):
        self.refuses([("x/other", tarfile.REGTYPE, BIN, "")])

    def test_two_fleetd(self):
        self.refuses(
            [("a/fleetd", tarfile.REGTYPE, BIN, ""), ("b/fleetd", tarfile.REGTYPE, BIN, "")]
        )

    def test_fleetd_symlink(self):
        self.refuses([("x/fleetd", tarfile.SYMTYPE, b"", "/bin/sh")])

    def test_fleetd_hardlink(self):
        self.refuses([("x/fleetd", tarfile.LNKTYPE, b"", "other")])

    def test_fleetd_directory(self):
        self.refuses([("x/fleetd", tarfile.DIRTYPE, b"", "")])

    def test_empty_binary(self):
        self.refuses([("x/fleetd", tarfile.REGTYPE, b"", "")])

    def test_not_an_archive(self):
        with Fixture() as fx:
            src = fx.dir / "d.tar.gz"
            src.write_bytes(b"not an archive")
            with self.assertRaises(ra.RepackError):
                ra.repack_archive(src, fx.dir / "out.tar.gz")

    def test_oversize_binary(self):
        with Fixture() as fx:
            binary = fx.dir / "bin"
            binary.write_bytes(b"x" * 11)
            with self.assertRaises(ra.RepackError):
                ra.repack_binary(binary, fx.dir / "out.tar.gz", max_bytes=10)
            binary.write_bytes(b"x" * 10)
            ra.repack_binary(binary, fx.dir / "out.tar.gz", max_bytes=10)

    def test_cli_exit_code_on_refusal(self):
        with Fixture() as fx:
            run = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--binary",
                    str(fx.dir / "missing"),
                    "--out",
                    str(fx.dir / "o.tar.gz"),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertNotEqual(run.returncode, 0)


if __name__ == "__main__":
    unittest.main()
