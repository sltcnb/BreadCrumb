"""Mutation fuzzing over the handlers, in ordinary CI.

Valid files are mutated -- bytes flipped, length fields made absurd, tails
truncated, files spliced onto themselves -- and every handler runs over the
result. A handler may reject anything it likes, but it must not raise, must not
take seconds on a few KB, and must never report a carve reaching past its
window, because the caller writes exactly that many bytes.
"""

import random
import time

import builders
from breadcrumb.reader import Window
from breadcrumb.signatures import SIGNATURES
from test_handlers import BytesReader


def _mutate(rng: random.Random, data: bytes) -> bytes:
    if not data:
        return data
    out = bytearray(data)
    choice = rng.randrange(6)
    if choice == 0:                                   # flip a bit
        at = rng.randrange(len(out))
        out[at] ^= 1 << rng.randrange(8)
    elif choice == 1:                                 # truncate
        del out[rng.randrange(len(out)):]
    elif choice == 2:                                 # absurd length field
        at = rng.randrange(len(out))
        out[at:at + 4] = b"\xff\xff\xff\x7f"[:len(out) - at]
    elif choice == 3:                                 # zero a run (sparse/wiped)
        at = rng.randrange(len(out))
        out[at:at + rng.randrange(64)] = bytes(min(64, len(out) - at))
    elif choice == 4:                                 # junk after the file
        out += rng.randbytes(64)
    else:                                             # two headers, one buffer
        out += out[len(out) // 2:]
    return bytes(out)


def _seeds():
    seeds = [b() for b in builders.BUILDERS.values()]
    seeds += [b() for b in builders.BEST_EFFORT_BUILDERS.values()]
    return seeds


def test_handlers_survive_mutated_input():
    rng = random.Random(0xC0FFEE)
    seeds = _seeds()
    deadline = time.monotonic() + 40
    cases = 0
    while cases < 1500 and time.monotonic() < deadline:
        body = _mutate(rng, rng.choice(seeds))
        if rng.randrange(3) == 0:
            body = _mutate(rng, body)
        reader = BytesReader(body)
        for sig in SIGNATURES:
            w = Window(reader, 0, reader.size)
            started = time.monotonic()
            carve = sig.handler(w)                    # must not raise
            if carve is not None:
                assert carve.size <= w.limit, (
                    f"{sig.name} carved {carve.size} from a {w.limit} byte window: "
                    f"{body[:48].hex()}")
            assert time.monotonic() - started < 2, f"{sig.name} took too long"
        cases += 1
    assert cases > 100, f"only managed {cases} cases"


def test_a_corrupt_png_chunk_length_is_rejected():
    """The case the fuzzer found first: a chunk length that runs off the end
    used to be returned as the carve size."""
    from breadcrumb import handlers
    png = bytearray(builders.make_png())
    # smash the length of the final chunk
    png[-12:-8] = b"\x00\x00\x40\x00"
    w = Window(BytesReader(bytes(png)), 0, len(png))
    carve = handlers.carve_png(w)
    assert carve is None or carve.size <= len(png)
