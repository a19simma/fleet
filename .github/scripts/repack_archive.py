#!/usr/bin/env python3
"""Repack a release binary into the archive fleetd's unpacker reads.

The output is a gzip stream holding one ustar regular file entry named `fleetd`: mode 0755,
owner 0:0, modification time 0, no extended or pax header. `crates/fleetd/src/update/unpack.rs`
refuses anything else. The input is either the binary itself or a cargo-dist archive
(`.tar.gz` or `.tar.xz`) that holds exactly one regular file named `fleetd` at any depth.
"""

import argparse
import gzip
import io
import pathlib
import sys
import tarfile

BINARY_NAME = "fleetd"
MAX_BINARY_BYTES = 256 * 1024 * 1024


class RepackError(Exception):
    """Input that would not yield a valid archive."""


def write_archive(data, out):
    info = tarfile.TarInfo(BINARY_NAME)
    info.size = len(data)
    info.mode = 0o755
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.type = tarfile.REGTYPE
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        tar.addfile(info, io.BytesIO(data))
    tmp = out.with_name(out.name + ".tmp")
    try:
        with tmp.open("wb") as handle:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=handle, mtime=0, compresslevel=9
            ) as gz:
                gz.write(raw.getvalue())
        tmp.replace(out)
    finally:
        tmp.unlink(missing_ok=True)


def repack_binary(binary, out, max_bytes=MAX_BINARY_BYTES):
    binary = pathlib.Path(binary)
    if not binary.is_file() or binary.is_symlink():
        raise RepackError(f"binary is not a regular file: {binary.name!r}")
    with binary.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if not data:
        raise RepackError("binary is empty")
    if len(data) > max_bytes:
        raise RepackError(f"binary is over {max_bytes} bytes")
    write_archive(data, pathlib.Path(out))


def repack_archive(source, out, max_bytes=MAX_BINARY_BYTES):
    try:
        with tarfile.open(source, "r:*") as tar:
            found = [
                m for m in tar.getmembers() if pathlib.PurePosixPath(m.name).name == BINARY_NAME
            ]
            if len(found) != 1:
                raise RepackError(f"expected one {BINARY_NAME} entry, found {len(found)}")
            member = found[0]
            if not member.isreg():
                raise RepackError(f"{BINARY_NAME} entry is not a regular file")
            if member.size == 0:
                raise RepackError("binary is empty")
            if member.size > max_bytes:
                raise RepackError(f"binary is over {max_bytes} bytes")
            handle = tar.extractfile(member)
            data = handle.read(max_bytes + 1)
    except (tarfile.TarError, EOFError, OSError) as err:
        raise RepackError(f"source is not a readable archive: {err}") from err
    write_archive(data, pathlib.Path(out))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--binary")
    source.add_argument("--from", dest="archive")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.binary:
            repack_binary(args.binary, args.out)
        else:
            repack_archive(args.archive, args.out)
    except RepackError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
