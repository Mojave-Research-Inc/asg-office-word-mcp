"""
File utility functions for Word Document Server.
"""
import os
from typing import Tuple, Optional
import shutil


# --- ASG hardening: CVE-2026-65695 path-traversal fix ---------------------------
# Upstream (through 1.1.11) passes tool `filename` arguments straight to
# Document()/save() with no sandboxing, so a caller who influences the filename
# can read/write arbitrary .docx files anywhere on the host (CWE-22). We confine
# every file path to a base directory (DOCX_FILES_PATH, default $HOME/GitHub) and
# reject any path that resolves outside it (absolute escapes, `..`, symlinks).
def _docx_base_dir() -> str:
    base = os.path.expandvars(os.environ.get("DOCX_FILES_PATH") or "") or os.path.join(os.path.expanduser("~"), "GitHub")
    return os.path.realpath(os.path.abspath(base))


def secure_path(path: str) -> str:
    """Confine `path` to the DOCX base dir; raise ValueError on traversal escape."""
    if path is None or str(path).strip() == "":
        raise ValueError("empty path")
    base = _docx_base_dir()
    os.makedirs(base, exist_ok=True)
    candidate = path if os.path.isabs(path) else os.path.join(base, path)
    real = os.path.realpath(os.path.abspath(candidate))
    if real != base and not real.startswith(base + os.sep):
        raise ValueError(
            f"path traversal blocked: {path!r} resolves outside the allowed directory {base!r}"
        )
    return real
# -------------------------------------------------------------------------------


def check_file_writeable(filepath: str) -> Tuple[bool, str]:
    """
    Check if a file can be written to.
    
    Args:
        filepath: Path to the file
        
    Returns:
        Tuple of (is_writeable, error_message)
    """
    # ASG hardening (CVE-2026-65695): reject traversal before any FS check.
    try:
        filepath = secure_path(filepath)
    except ValueError as exc:
        return False, str(exc)
    # If file doesn't exist, check if directory is writeable
    if not os.path.exists(filepath):
        directory = os.path.dirname(filepath)
        # If no directory is specified (empty string), use current directory
        if directory == '':
            directory = '.'
        if not os.path.exists(directory):
            return False, f"Directory {directory} does not exist"
        if not os.access(directory, os.W_OK):
            return False, f"Directory {directory} is not writeable"
        return True, ""
    
    # If file exists, check if it's writeable
    if not os.access(filepath, os.W_OK):
        return False, f"File {filepath} is not writeable (permission denied)"
    
    # Try to open the file for writing to see if it's locked
    try:
        with open(filepath, 'a'):
            pass
        return True, ""
    except IOError as e:
        return False, f"File {filepath} is not writeable: {str(e)}"
    except Exception as e:
        return False, f"Unknown error checking file permissions: {str(e)}"


def create_document_copy(source_path: str, dest_path: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
    """
    Create a copy of a document.
    
    Args:
        source_path: Path to the source document
        dest_path: Optional path for the new document. If not provided, will use source_path + '_copy.docx'
        
    Returns:
        Tuple of (success, message, new_filepath)
    """
    if not os.path.exists(source_path):
        return False, f"Source document {source_path} does not exist", None
    
    if not dest_path:
        # Generate a new filename if not provided
        base, ext = os.path.splitext(source_path)
        dest_path = f"{base}_copy{ext}"
    
    try:
        # Simple file copy
        shutil.copy2(source_path, dest_path)
        return True, f"Document copied to {dest_path}", dest_path
    except Exception as e:
        return False, f"Failed to copy document: {str(e)}", None


def ensure_docx_extension(filename: str) -> str:
    """
    Ensure filename has .docx extension.
    
    Args:
        filename: The filename to check
        
    Returns:
        Filename with .docx extension
    """
    if not filename.endswith('.docx'):
        filename = filename + '.docx'
    # ASG hardening (CVE-2026-65695): confine to the sandbox base dir. This is the
    # near-universal chokepoint every tool calls, so it blocks traversal globally.
    return secure_path(filename)
