"""ASG CVE-2026-65695 regression: path traversal must be blocked."""
import os, tempfile, pytest
os.environ.setdefault("DOCX_FILES_PATH", tempfile.mkdtemp(prefix="docx-sandbox-"))
from word_document_server.utils.file_utils import secure_path, ensure_docx_extension

BASE = os.path.realpath(os.environ["DOCX_FILES_PATH"])

def test_blocks_absolute_escape():
    with pytest.raises(ValueError):
        secure_path("/etc/passwd")

def test_blocks_dotdot_escape():
    with pytest.raises(ValueError):
        secure_path("../../../../etc/passwd")

def test_blocks_nested_dotdot():
    with pytest.raises(ValueError):
        secure_path("sub/../../../../etc/hosts")

def test_allows_relative_in_base():
    p = secure_path("report.docx")
    assert p == os.path.join(BASE, "report.docx")

def test_allows_subdir_in_base():
    p = secure_path("proj/report.docx")
    assert p.startswith(BASE + os.sep)

def test_ensure_docx_sandboxes_and_extends():
    p = ensure_docx_extension("notes")
    assert p == os.path.join(BASE, "notes.docx")

def test_ensure_docx_blocks_traversal():
    with pytest.raises(ValueError):
        ensure_docx_extension("../../secret")
