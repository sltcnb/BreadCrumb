"""valid_job_id must only accept the exact uuid4 shape the app generates,
since job ids are used to build filesystem paths under UPLOAD_DIR/
CARVED_DIR/JOBS_DIR — anything else is a path-traversal vector."""

import uuid

import pytest
from werkzeug.exceptions import BadRequest

from carvx_web.jobs import valid_job_id


def test_accepts_a_real_uuid4():
    job_id = str(uuid.uuid4())
    assert valid_job_id(job_id) == job_id


@pytest.mark.parametrize("bad_id", [
    "",
    "not-a-uuid",
    "12345678-1234-1234-1234-1234567890",       # one hex digit short
    "12345678-1234-1234-1234-1234567890zz",     # non-hex chars
    "../../etc/passwd",
    "12345678-1234-1234-1234-1234567890ab/../x",
    "12345678-1234-1234-1234-1234567890AB",     # uppercase hex rejected
    "  12345678-1234-1234-1234-1234567890ab",   # leading whitespace
    None,
])
def test_rejects_anything_that_is_not_a_bare_uuid4(bad_id):
    with pytest.raises(BadRequest):
        valid_job_id(bad_id)
