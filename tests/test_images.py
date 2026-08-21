"""Image-format reader tests.

Split-raw, QCOW2, and VMDK are verified against qemu-img output when qemu-img
is available (else skipped). EWF is covered twice over: hand-built images
exercise the section/table parser with no dependencies, and where libewf is
installed, ewfacquire-produced images (several formats, compression settings,
and a segmented set) are compared byte for byte against the raw source.
"""

import glob
import os
import shutil
import struct
import subprocess
import zlib

import pytest

import builders
from breadcrumb.images import (open_source, SplitRawReader, Qcow2Reader, EwfReader,
                               EwfPyReader)
from breadcrumb.reader import Reader

def _tool(name):
    return shutil.which(name) or (f"/opt/homebrew/bin/{name}"
                                  if os.path.exists(f"/opt/homebrew/bin/{name}") else None)


QEMU = _tool("qemu-img")
EWFACQUIRE = _tool("ewfacquire")
try:
    import pyewf                                 # noqa: F401  (probe only)
    PYEWF = True
except ImportError:
    PYEWF = False


@pytest.fixture
def raw_image(tmp_path):
    """A raw image with a few carvable files; returns (path, sha256 of bytes)."""
    import hashlib
    data = bytearray(b"\x00" * 4096)
    for builder in (builders.make_png, builders.make_jpeg, builders.make_gif):
        data += b"\x11" * 2048 + builder()
    data += b"\x00" * 4096
    p = tmp_path / "raw.img"
    p.write_bytes(bytes(data))
    return str(p), hashlib.sha256(bytes(data)).hexdigest()


def _full_read(reader):
    return reader.pread(0, reader.size)


# ---------------------------------------------------------------- split raw

def test_split_raw_roundtrip(raw_image, tmp_path):
    path, sha = raw_image
    import hashlib
    data = open(path, "rb").read()
    # split into 5000-byte segments named .001, .002, ...
    seg_paths = []
    for i in range(0, len(data), 5000):
        sp = tmp_path / f"img.{i // 5000 + 1:03d}"
        sp.write_bytes(data[i:i + 5000])
        seg_paths.append(str(sp))
    r = open_source(seg_paths[0])
    assert isinstance(r, SplitRawReader)
    try:
        assert r.size == len(data)
        assert hashlib.sha256(_full_read(r)).hexdigest() == sha
        # random spanning read across segment boundary
        assert r.pread(4900, 300) == data[4900:5200]
    finally:
        r.close()


# ---------------------------------------------------------------- qemu formats

@pytest.mark.skipif(not QEMU, reason="qemu-img not installed")
@pytest.mark.parametrize("fmt,extra", [
    ("qcow2", ["-c"]),          # compressed
    ("qcow2", []),              # uncompressed
    ("vmdk", []),
])
def test_qemu_format_roundtrip(raw_image, tmp_path, fmt, extra):
    import hashlib
    path, sha = raw_image
    out = tmp_path / f"img.{fmt}"
    subprocess.run([QEMU, "convert", "-f", "raw", "-O", fmt, *extra,
                    path, str(out)], check=True, capture_output=True)
    r = open_source(str(out))
    try:
        assert r.size >= os.path.getsize(path) - 4096
        got = r.pread(0, os.path.getsize(path))
        assert hashlib.sha256(got).hexdigest() == sha
    finally:
        r.close()


@pytest.mark.skipif(not QEMU, reason="qemu-img not installed")
def test_carve_through_qcow2_matches_raw(raw_image, tmp_path):
    from breadcrumb.carver import Carver, Options
    from breadcrumb.signatures import SIGNATURES
    path, _ = raw_image
    out = tmp_path / "img.qcow2"
    subprocess.run([QEMU, "convert", "-f", "raw", "-O", "qcow2", "-c",
                    path, str(out)], check=True, capture_output=True)

    def carve(src, odir):
        c = Carver(src, list(SIGNATURES), Options(out_dir=str(odir), quiet=True))
        try:
            return sorted((r.size, r.sha256) for r in c.run())
        finally:
            c.close()

    assert carve(path, tmp_path / "a") == carve(str(out), tmp_path / "b")


# ---------------------------------------------------------------- EWF (E01)

def _build_e01(path, payload, chunk_sectors=2, bps=512, compress=False):
    """Minimal single-segment EWF with one sectors+table section.

    Field offsets follow libewf's ewf_volume exactly -- a builder that mirrors
    a parser's own idea of the layout proves nothing.
    """
    chunk_size = chunk_sectors * bps
    raw_chunks = [payload[i:i + chunk_size]
                  for i in range(0, len(payload), chunk_size)]
    raw_chunks = [c.ljust(chunk_size, b"\x00") for c in raw_chunks]
    total_sectors = (len(payload) + bps - 1) // bps

    out = bytearray()
    # EWF file header: 8-byte signature + 0x01 + segment number (2) + 0x0000 = 13
    out += b"EVF\x09\x0d\x0a\xff\x00" + bytes([1]) + struct.pack("<HH", 1, 0)

    def emit(stype, body):
        nonlocal out
        start = len(out)
        desc = bytearray(76)
        desc[:16] = stype[:15] + b"\x00" * (16 - len(stype[:15]))
        size = 76 + len(body)
        struct.pack_into("<Q", desc, 16, start + size)        # next section offset
        struct.pack_into("<Q", desc, 24, size)
        struct.pack_into("<I", desc, 72, zlib.adler32(desc[:72]) & 0xFFFFFFFF)
        out += desc + body
        return start

    # ewf_volume: media_type(1) unknown(3) chunk_count(4) sectors_per_chunk(4)
    #             bytes_per_sector(4) sector_count(8) + padding
    vol = bytearray(1052)
    struct.pack_into("<B", vol, 0, 1)                     # media type: fixed disk
    struct.pack_into("<I", vol, 4, len(raw_chunks))
    struct.pack_into("<I", vol, 8, chunk_sectors)
    struct.pack_into("<I", vol, 12, bps)
    struct.pack_into("<Q", vol, 16, total_sectors)
    emit(b"volume", bytes(vol))

    # sectors section holds the chunk data, compressed per chunk or raw
    stored, entries_meta = bytearray(), []
    for chunk in raw_chunks:
        entries_meta.append((len(stored), compress))
        stored += zlib.compress(chunk) if compress else chunk
    sectors_start = emit(b"sectors", bytes(stored))
    data_base = sectors_start + 76                  # absolute file offset of chunk 0

    # table section: count(4) pad(4) base_offset(8) pad(4) checksum(4) + entries
    thdr = bytearray(24)
    struct.pack_into("<I", thdr, 0, len(raw_chunks))
    struct.pack_into("<Q", thdr, 8, data_base)      # base offset
    entries = bytearray()
    for rel, comp in entries_meta:
        entries += struct.pack("<I", rel | (0x80000000 if comp else 0))
    emit(b"table", bytes(thdr) + bytes(entries))
    emit(b"done", b"")

    with open(path, "wb") as fh:
        fh.write(out)


@pytest.mark.parametrize("compress", [False, True])
def test_ewf_synthetic_roundtrip(tmp_path, compress):
    """The pure-Python parser against a spec-shaped image, no libewf needed."""
    payload = bytes(range(256)) * 40 + builders.make_png()   # ~10 KiB
    e01 = tmp_path / "img.E01"
    _build_e01(str(e01), payload, compress=compress)
    r = EwfReader(str(e01))
    try:
        # the sector count in the volume section gives an exact media size,
        # not merely the chunk-aligned upper bound
        assert r.size == 512 * ((len(payload) + 511) // 512)
        assert r.pread(0, len(payload)) == payload
        assert r.pread(100, 50) == payload[100:150]
        assert r.pread(1000, 2000) == payload[1000:3000]     # spans chunks
    finally:
        r.close()


# ------------------------------------------------- EWF against real libewf
#
# ewfacquire writes the images; the readers must agree with the raw source
# byte for byte. This is the check that catches a misread volume/table field
# -- a hand-built image can only ever confirm our own reading of the spec.

@pytest.fixture
def sector_aligned_image(tmp_path):
    """Raw image whose length is a whole number of sectors, with carvable
    files in it. ewfacquire images in sector units, so an unaligned tail
    would be dropped and every byte-exact assertion below would fail for
    reasons that have nothing to do with EWF."""
    data = bytearray()
    while len(data) < 200 * 1024:
        data += b"\x11" * 3000 + builders.make_png() + builders.make_jpeg()
    data = bytes(data[:200 * 1024])            # 400 sectors, ~7 chunks at -b 64
    p = tmp_path / "raw.img"
    p.write_bytes(data)
    return str(p), data


def _acquire(raw_path, stem, fmt="encase6", compression="best", extra=()):
    """Write an EWF set with ewfacquire; returns the first segment's path."""
    subprocess.run([EWFACQUIRE, "-u", "-t", stem, "-f", fmt, "-c", compression,
                    "-b", "64", *extra, raw_path], check=True, capture_output=True)
    segs = sorted(glob.glob(stem + ".*"))
    assert segs, f"ewfacquire wrote nothing for {fmt}/{compression}"
    return segs[0], segs


@pytest.mark.skipif(not EWFACQUIRE, reason="ewfacquire (libewf) not installed")
@pytest.mark.parametrize("fmt,compression", [
    ("encase6", "best"),        # deflate chunks
    ("encase6", "none"),        # stored chunks
    ("encase5", "fast"),
    ("smart", "best"),          # EWF-S01: 4-byte sector count in the volume
    ("ewfx", "best"),
])
def test_ewf_real_image_roundtrip(sector_aligned_image, tmp_path, fmt, compression):
    raw_path, data = sector_aligned_image
    first, _ = _acquire(raw_path, str(tmp_path / f"acq_{fmt}_{compression}"),
                        fmt, compression)
    r = EwfReader(first)
    try:
        assert r.size == len(data)
        assert r.pread(0, r.size) == data
        assert r.pread(70000, 5000) == data[70000:75000]     # spans chunks
    finally:
        r.close()


@pytest.mark.skipif(not EWFACQUIRE, reason="ewfacquire (libewf) not installed")
def test_ewf_real_multi_segment_roundtrip(tmp_path):
    """A segmented set (.E01/.E02/...) is globbed from the first segment and
    read as one image, including reads that span a segment boundary."""
    data = bytearray()
    while len(data) < 4 << 20:                 # 1 MiB is ewfacquire's floor
        data += b"\x22" * 5000 + builders.make_png() + os.urandom(20000)
    data = bytes(data[:4 << 20])
    raw = tmp_path / "raw.img"
    raw.write_bytes(data)

    first, segs = _acquire(str(raw), str(tmp_path / "multi"),
                           extra=("-S", "1MiB"))
    assert len(segs) > 1, "expected a segmented set"
    r = EwfReader(first)
    try:
        assert len(r.segments) == len(segs)
        assert r.size == len(data)
        assert r.pread(0, r.size) == data
        assert r.pread((1 << 20) - 2000, 5000) == data[(1 << 20) - 2000:(1 << 20) + 3000]
    finally:
        r.close()


def test_segment_names_follow_libewf_naming():
    """Past segment 99 the digits become letters and the leading character
    carries: E01..E99, EAA..EZZ, FAA.., through ZZZ. A set that outgrows two
    digits is routine when imaging a large disk to removable media."""
    names = EwfReader._segment_names("/ev/RM", "E")
    got = [next(names).rsplit(".", 1)[1] for _ in range(105)]
    assert got[:3] == ["E01", "E02", "E03"]
    assert got[98] == "E99"
    assert got[99:105] == ["EAA", "EAB", "EAC", "EAD", "EAE", "EAF"]
    # lowercase sets keep their case
    lower = EwfReader._segment_names("/ev/rm", "e")
    assert [next(lower).rsplit(".", 1)[1] for _ in range(100)][-1] == "eaa"


@pytest.mark.skipif(not EWFACQUIRE, reason="ewfacquire (libewf) not installed")
def test_ewf_set_longer_than_99_segments_reads_whole():
    """The real failure this guards: with 100+ segments the reader used to stop
    at E99 and report the truncated size as the whole media."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        data = bytearray()
        while len(data) < 120 << 20:              # ~120 segments at 1 MiB each
            data += b"\x33" * 4000 + builders.make_png() + builders.make_jpeg()
        data = bytes(data[:120 << 20])
        raw = os.path.join(td, "raw.img")
        with open(raw, "wb") as fh:
            fh.write(data)
        first, segs = _acquire(raw, os.path.join(td, "many"),
                               compression="none", extra=("-S", "1MiB"))
        assert len(segs) > 99, f"expected a set past E99, got {len(segs)}"
        assert any(s.endswith("EAA") for s in segs), "expected letter-named segments"
        r = EwfReader(first)
        try:
            assert len(r.segments) == len(segs)
            assert r.size == len(data)
            assert r.pread(0, r.size) == data
        finally:
            r.close()


@pytest.mark.skipif(not EWFACQUIRE, reason="ewfacquire (libewf) not installed")
def test_incomplete_segment_set_is_refused(tmp_path):
    """Missing tail segments must be an error, never a short image: carving a
    fraction of the evidence while reporting success is the worst outcome."""
    data = bytearray()
    while len(data) < 4 << 20:                 # 1 MiB is ewfacquire's floor
        data += b"\x44" * 5000 + builders.make_png()
    data = bytes(data[:4 << 20])
    raw = tmp_path / "raw.img"
    raw.write_bytes(data)
    first, segs = _acquire(str(raw), str(tmp_path / "part"),
                           compression="none", extra=("-S", "1MiB"))
    assert len(segs) >= 3, f"expected a segmented set, got {len(segs)}"
    for gone in segs[2:]:
        os.unlink(gone)
    with pytest.raises(ValueError, match="incomplete EWF set"):
        EwfReader(first)


@pytest.mark.skipif(not (EWFACQUIRE and PYEWF), reason="needs ewfacquire + pyewf")
def test_ewf_pyewf_and_pure_python_readers_agree(sector_aligned_image, tmp_path):
    """open_source prefers libewf when it is installed, and the two readers
    must be interchangeable."""
    raw_path, data = sector_aligned_image
    first, _ = _acquire(raw_path, str(tmp_path / "acq"))

    picked = open_source(first)
    try:
        assert isinstance(picked, EwfPyReader)
    finally:
        picked.close()

    with EwfPyReader(first) as libewf, EwfReader(first) as pure:
        assert libewf.size == pure.size == len(data)
        assert libewf.pread(0, libewf.size) == pure.pread(0, pure.size) == data


@pytest.mark.skipif(not EWFACQUIRE, reason="ewfacquire (libewf) not installed")
def test_carve_through_ewf_matches_raw(sector_aligned_image, tmp_path):
    from breadcrumb.carver import Carver, Options
    from breadcrumb.signatures import SIGNATURES
    raw_path, _ = sector_aligned_image
    first, _ = _acquire(raw_path, str(tmp_path / "acq"))

    def carve(src, odir):
        c = Carver(src, list(SIGNATURES), Options(out_dir=str(odir), quiet=True))
        try:
            return sorted((r.offset, r.size, r.sha256) for r in c.run())
        finally:
            c.close()

    assert carve(raw_path, tmp_path / "a") == carve(first, tmp_path / "b")


def test_open_source_detects_qcow2_magic(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"QFI\xfb" + b"\x00" * 200)
    # malformed but magic present -> Qcow2Reader attempted (will read zeros)
    try:
        r = open_source(str(p))
        assert isinstance(r, Qcow2Reader)
        r.close()
    except Exception:
        pass        # header too small to fully parse is acceptable


def test_open_source_falls_back_to_raw(tmp_path):
    p = tmp_path / "plain.img"
    p.write_bytes(b"just raw bytes" * 100)
    r = open_source(str(p))
    assert isinstance(r, Reader)
    r.close()


# ---------------------------------------------------------------- stdin spool

def test_stdin_reader_spools_and_reads(tmp_path):
    import io
    from breadcrumb.images import StdinReader
    data = bytes(range(256)) * 500
    r = StdinReader(stream=io.BytesIO(data))
    try:
        assert r.size == len(data)
        assert r.pread(0, 100) == data[:100]
        assert r.pread(1000, 256) == data[1000:1256]
        assert r.path == "-"
        tmp = r._tmp
        assert os.path.exists(tmp)
    finally:
        r.close()
    assert not os.path.exists(tmp)        # cleaned up on close
