#!/usr/bin/env python3
"""Write the fleetd update manifest for a set of release archives.

The output has the shape `RawManifest` in `crates/fleetd/src/update.rs` parses:
`version`, `min_protocol`, `seq` and `targets`, where each target carries `sha256`,
`size` and `url`. The checks below mirror the fleetd limits, so a manifest this
script writes is one `verify_manifest` accepts once it is signed.
"""

import argparse
import hashlib
import json
import pathlib
import re
import sys

MAX_TARGETS = 16
MAX_TARGET_NAME_BYTES = 64
MAX_URL_BYTES = 2048
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024
MAX_SEQ = 2**64 - 1
CHUNK = 1024 * 1024

TARGET_NAME = re.compile(r"[a-z0-9_.-]+")
ARCHIVE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(-[0-9A-Za-z.-]+)?"
)


class ManifestError(Exception):
    """Input that would make fleetd refuse the manifest."""


def check_target_name(name):
    if not (
        0 < len(name.encode()) <= MAX_TARGET_NAME_BYTES and TARGET_NAME.fullmatch(name)
    ):
        raise ManifestError(f"target name is not valid: {name!r}")


def check_base_url(base_url):
    rest = base_url.removeprefix("https://")
    if rest == base_url or not rest:
        raise ManifestError("base url must start with https:// and name a host")
    if not all(33 <= ord(c) <= 126 and c not in "\\@#?%" for c in base_url):
        raise ManifestError("base url holds a character fleetd refuses")
    if base_url.endswith("/"):
        raise ManifestError("base url must not end with a slash")


def hash_archive(path, max_archive_bytes):
    if not path.is_file():
        raise ManifestError(f"archive is not a file: {path.name!r}")
    if not ARCHIVE_NAME.fullmatch(path.name) or len(path.name) > 255:
        raise ManifestError(f"archive file name is not valid: {path.name!r}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            size += len(chunk)
            if size > max_archive_bytes:
                raise ManifestError(f"archive is over {max_archive_bytes} bytes")
            digest.update(chunk)
    if size == 0:
        raise ManifestError(f"archive is empty: {path.name!r}")
    return digest.hexdigest(), size


def build_manifest(
    *,
    version,
    seq,
    min_protocol,
    base_url,
    entries,
    max_archive_bytes=MAX_ARCHIVE_BYTES,
    max_manifest_bytes=MAX_MANIFEST_BYTES,
):
    """Return the manifest text for `entries`, a list of `(target name, archive path)`."""
    if not SEMVER.fullmatch(version):
        raise ManifestError(f"version is not semver: {version!r}")
    if not 1 <= seq <= MAX_SEQ:
        raise ManifestError("seq must be between 1 and 2^64-1")
    if not 0 <= min_protocol <= 2**32 - 1:
        raise ManifestError("min_protocol is out of range")
    check_base_url(base_url)
    if not 1 <= len(entries) <= MAX_TARGETS:
        raise ManifestError(f"targets must hold 1 to {MAX_TARGETS} entries")
    targets = {}
    for name, raw_path in entries:
        check_target_name(name)
        if name in targets:
            raise ManifestError(f"duplicate target: {name!r}")
        path = pathlib.Path(raw_path)
        sha256, size = hash_archive(path, max_archive_bytes)
        url = f"{base_url}/{path.name}"
        if len(url.encode()) > MAX_URL_BYTES:
            raise ManifestError(f"url is over {MAX_URL_BYTES} bytes")
        targets[name] = {"sha256": sha256, "size": size, "url": url}
    doc = {
        "version": version,
        "min_protocol": min_protocol,
        "seq": seq,
        "targets": dict(sorted(targets.items())),
    }
    text = json.dumps(doc, indent=2) + "\n"
    if len(text.encode()) > max_manifest_bytes:
        raise ManifestError(f"manifest is over {max_manifest_bytes} bytes")
    return text


def parse_target(value):
    name, sep, path = value.partition("=")
    if not sep or not name or not path:
        raise argparse.ArgumentTypeError("expected NAME=ARCHIVE_PATH")
    return name, path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True)
    parser.add_argument("--seq", required=True, type=int)
    parser.add_argument("--min-protocol", type=int, default=1)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--target", action="append", default=[], type=parse_target)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        text = build_manifest(
            version=args.version,
            seq=args.seq,
            min_protocol=args.min_protocol,
            base_url=args.base_url,
            entries=args.target,
        )
    except ManifestError as err:
        print(f"update_manifest: {err}", file=sys.stderr)
        return 1
    pathlib.Path(args.out).write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
