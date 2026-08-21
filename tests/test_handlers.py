"""Per-handler unit tests: valid input, truncation, corruption."""

import io
import os
import random
import zipfile

import pytest

import builders
from breadcrumb import handlers
from breadcrumb.reader import Window
from breadcrumb.signatures import BY_NAME


class BytesReader:
    """Reader stand-in backed by a bytes object."""

    def __init__(self, data: bytes):
        self.data = data
        self.size = len(data)

    def pread(self, offset, length):
        return self.data[offset:offset + length]


def window(data: bytes, base: int = 0, limit: int | None = None) -> Window:
    return Window(BytesReader(data), base, limit if limit is not None else len(data) - base)


def junk(n: int) -> bytes:
    """Seeded filler. See the note on the `image` fixture in test_carver.py."""
    return random.Random(7).randbytes(n)


CASES = [
    # (builder key, signature name, expected ext)
    ("png", "png", "png"),
    ("jpg", "jpg", "jpg"),
    ("gif", "gif", "gif"),
    ("bmp", "bmp", "bmp"),
    ("pdf", "pdf", "pdf"),
    ("rtf", "rtf", "rtf"),
    ("ole", "ole", "doc"),
    ("zip", "zip", "zip"),
    ("docx", "zip", "docx"),
    ("gz", "gz", "gz"),
    ("sqlite", "sqlite", "sqlite"),
    ("mp4", "mp4", "mp4"),
    ("wav", "riff", "wav"),
    ("elf", "elf", "elf"),
    ("7z", "7z", "7z"),
    ("mp3", "mp3", "mp3"),
    ("macho", "macho", "macho"),
    ("ico", "ico", "ico"),
    ("ogg", "ogg", "ogg"),
    ("mkv", "mkv", "webm"),
    ("evtx", "evtx", "evtx"),
    ("hive", "hive", "hive"),
    ("plist", "plist", "plist"),
]

# Best-effort handlers: no exact end marker in the format, so size may include
# trailing data up to the next signature / EOF. Just confirm they don't crash
# and return a plausible carve on valid input.
BEST_EFFORT = [("flac", "flac"), ("psd", "psd")]


@pytest.mark.parametrize("key,sig_name", BEST_EFFORT)
def test_best_effort_handlers(key, sig_name):
    builder = builders.BEST_EFFORT_BUILDERS.get(key)
    if builder is None:
        pytest.skip(f"no builder for {key}")
    data = builder()
    carve = BY_NAME[sig_name].handler(window(data))
    assert carve is not None and carve.size >= len(data) - 4
    assert BY_NAME[sig_name].handler(window(b"")) is None


@pytest.mark.parametrize("key,sig_name,ext", CASES)
def test_exact_size_on_valid_file(key, sig_name, ext):
    data = builders.BUILDERS[key]()
    sig = BY_NAME[sig_name]
    # trailing junk must not change the carved size
    carve = sig.handler(window(data + junk(2000)))
    assert carve is not None, f"{key}: handler rejected valid file"
    assert carve.size == len(data), f"{key}: size {carve.size} != {len(data)}"
    assert carve.ext == ext


@pytest.mark.parametrize("key,sig_name,ext", CASES)
def test_truncated_input_never_overruns(key, sig_name, ext):
    """Cut the file short: handler must reject or return a size within bounds."""
    data = builders.BUILDERS[key]()
    sig = BY_NAME[sig_name]
    for cut in (len(data) // 2, 20, 10):
        w = window(data[:cut])
        carve = sig.handler(w)
        if carve is not None:
            assert carve.size <= cut


@pytest.mark.parametrize("key,sig_name,ext", CASES)
def test_corrupted_tail_never_crashes(key, sig_name, ext):
    data = bytearray(builders.BUILDERS[key]())
    # smash the second half
    half = len(data) // 2
    data[half:] = os.urandom(len(data) - half)
    sig = BY_NAME[sig_name]
    carve = sig.handler(window(bytes(data)))   # must not raise
    if carve is not None:
        assert 0 < carve.size <= len(data)


def test_jpeg_embedded_thumbnail_not_terminating():
    """EOI inside an APP segment (EXIF thumbnail) must not end the carve."""
    inner = builders.make_jpeg()
    app1 = b"\xff\xe1" + (len(inner) + 2).to_bytes(2, "big") + inner
    data = builders.make_jpeg()
    data = data[:2] + app1 + data[2:]
    carve = handlers.carve_jpeg(window(data + b"\x00" * 100))
    assert carve is not None and carve.size == len(data)


def test_zip_eocd_cross_check_picks_right_end():
    """A stored (uncompressed) inner zip must not truncate the outer one."""
    inner = builders.make_zip()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("inner.zip", inner)
        z.writestr("more.txt", "x" * 500)
    data = buf.getvalue()
    carve = handlers.carve_zip(window(data + os.urandom(500)))
    assert carve is not None and carve.size == len(data) and carve.validated


def test_pdf_stops_before_next_pdf():
    a, b = builders.make_pdf(), builders.make_pdf()
    carve = handlers.carve_pdf(window(a + b))
    assert carve is not None and carve.size == len(a)


def test_gzip_multimember():
    data = builders.make_gzip() + builders.make_gzip()
    carve = handlers.carve_gzip(window(data + os.urandom(100)))
    assert carve is not None and carve.size == len(data)


def test_sqlite_rejects_bad_page_size():
    data = bytearray(builders.make_sqlite())
    data[16:18] = (1234).to_bytes(2, "big")    # not a power of two
    assert handlers.carve_sqlite(window(bytes(data))) is None


def test_bmp_with_nonzero_reserved_fields_is_carved():
    """Real-world editors often stamp reserved1/reserved2; they must not
    cause a false-negative rejection."""
    data = bytearray(builders.make_bmp())
    data[6:10] = b"\xff\xff\xab\xcd"           # reserved1/reserved2 nonzero
    carve = handlers.carve_bmp(window(bytes(data) + os.urandom(2000)))
    assert carve is not None
    assert carve.size == len(data)
    assert carve.ext == "bmp"


# MPEG audio frame headers, as (byte 1, bitrate index, frame length). Byte 1
# carries the sync bits plus version and layer; the length follows from the
# bitrate and sample rate, so it is spelled out here rather than derived from
# the handler under test.
_MPEG1_L3 = 0xFB                               # MPEG1 Layer III, 44100 Hz
_MPEG2_L3 = 0xF3                               # MPEG2 Layer III, 22050 Hz


def mpeg_frame(byte1: int, br_idx: int, length: int) -> bytes:
    """One frame: 4-byte header (no padding, no CRC) plus silent payload."""
    return bytes([0xFF, byte1, br_idx << 4, 0x00]) + b"\x00" * (length - 4)


def id3v2(body: bytes = b"") -> bytes:
    n = len(body)                              # synchsafe 4x7-bit size
    return b"ID3\x03\x00\x00" + bytes([(n >> 21) & 0x7F, (n >> 14) & 0x7F,
                                        (n >> 7) & 0x7F, n & 0x7F]) + body


def test_mp3_vbr_bitrate_changes_stay_one_stream():
    """Bitrate may change frame to frame; version/layer/rate may not."""
    data = id3v2() + (mpeg_frame(_MPEG1_L3, 9, 417)      # 144 * 128000 // 44100
                      + mpeg_frame(_MPEG1_L3, 11, 626)   # 144 * 192000 // 44100
                      + mpeg_frame(_MPEG1_L3, 9, 417)) * 4
    carve = handlers.carve_mp3(window(data + junk(2000)))
    assert carve is not None and carve.size == len(data)


def test_mp3_stops_at_frame_shaped_trailing_data():
    """Trailing data can sync and decode as a valid header by chance. If it
    declares a different version/layer/rate than the stream, it is not a
    frame of this file and must not extend the carve."""
    data = builders.make_mp3()                 # MPEG1 Layer III, 44100 Hz
    other = mpeg_frame(_MPEG2_L3, 8, 208) * 4  # 72 * 64000 // 22050
    assert handlers._mp3_frame(other[:4]) is not None, "junk header not valid"
    carve = handlers.carve_mp3(window(data + other))
    assert carve is not None and carve.size == len(data)


def test_mp3_absorbs_trailing_id3v1_only_when_it_fits():
    data = builders.make_mp3()
    whole = data + b"TAG" + b"\x00" * 125      # ID3v1 is exactly 128 bytes
    carve = handlers.carve_mp3(window(whole + junk(500)))
    assert carve is not None and carve.size == len(whole)

    cut = data + b"TAG" + b"\x00" * 60         # truncated: leave it out
    carve = handlers.carve_mp3(window(cut))
    assert carve is not None and carve.size == len(data)


# --------------------------------------------------------- Office documents

@pytest.mark.parametrize("stream,ext", [
    ("WordDocument", "doc"),
    ("Workbook", "xls"),
    ("Book", "xls"),                            # Excel 5.0/95
    ("PowerPoint Document", "ppt"),
    ("__substg1.0_0037001F", "msg"),            # Outlook message
    ("VisioDocument", "vsd"),
    ("SomethingElse", "ole"),                   # unknown: generic container
])
def test_ole_extension_comes_from_the_stream_name(stream, ext):
    """An OLE2 container is only a container; which Office application wrote it
    is decided by the stream names in its directory. Getting this right is what
    makes the carve triageable."""
    data = builders.make_ole(stream)
    carve = handlers.carve_ole(window(data + junk(2048)))
    assert carve is not None, f"{stream}: rejected"
    assert carve.ext == ext
    assert carve.size == len(data)


def test_rtf_survives_escapes_and_binary_blobs():
    """Naive brace counting breaks on \\{ escapes and on \\binN payloads that
    contain unbalanced braces; both appear in real documents."""
    rtf = builders.make_rtf()
    assert b"\\bin" in rtf and b"}}}" in rtf
    carve = handlers.carve_rtf(window(rtf + b"TRAILING JUNK" * 8))
    assert carve is not None and carve.size == len(rtf) and carve.validated


def test_rtf_without_a_closing_brace_is_rejected():
    truncated = builders.make_rtf()[:-1]
    assert handlers.carve_rtf(window(truncated)) is None


def test_office_group_resolves_to_every_document_container():
    from breadcrumb.signatures import resolve_types
    names = {s.name for s in resolve_types("office")}
    assert names == {"ole", "zip", "pdf", "rtf"}
    # and the per-application aliases still work on their own
    assert {s.name for s in resolve_types("doc,xls,ppt,docx,xlsx,pptx,pdf")} == \
        {"ole", "zip", "pdf"}


def test_empty_and_tiny_windows():
    for sig in BY_NAME.values():
        assert sig.handler(window(b"")) is None
        assert sig.handler(window(b"\x00")) is None


# Leading bytes carve_macho recognizes: the fat/universal magic plus the four
# thin Mach-O magics. A host binary that does not start with one of these (an
# ELF /bin/ls on Linux, say) is not a Mach-O and must not be fed to this test.
_MACHO_MAGICS = (
    b"\xca\xfe\xba\xbe",  # fat / universal
    b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",  # thin, little-endian (64/32)
    b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",  # thin, big-endian (64/32)
)


def test_macho_fat_binary():
    if not os.path.exists("/bin/ls"):
        pytest.skip("no /bin/ls")
    data = open("/bin/ls", "rb").read()
    if data[:4] not in _MACHO_MAGICS:
        pytest.skip("host /bin/ls is not a Mach-O binary (e.g. ELF on Linux)")
    carve = handlers.carve_macho(window(data + os.urandom(1000)))
    assert carve is not None and carve.size == len(data)


def test_random_noise_yields_no_validated_carves():
    noise = os.urandom(1 << 20)
    for name, sig in BY_NAME.items():
        for magic in sig.magics:
            idx = noise.find(magic)
            if idx < 0:
                continue
            carve = sig.handler(window(noise, idx))
            if carve is not None:
                assert not carve.validated or carve.size <= len(noise) - idx
