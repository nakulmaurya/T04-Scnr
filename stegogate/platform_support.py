"""Native host adapters; unsupported isolation is never silently bypassed."""

from __future__ import annotations

import math
import os
from pathlib import Path
import stat
import sys


def capabilities():
    linux = sys.platform == "linux"
    return {
        "platform": sys.platform,
        "native_analysis": True,
        "linux_isolation_eligible": linux,
        "demo_worker_eligible": linux,
        "note": (
            "Linux isolation is eligible; installed dependencies and kernel checks still apply."
            if linux
            else "Native tensor analysis, reference comparison, JSON detector scoring and reports are available. "
            "ModelAudit/Picklescan isolation and demo preparation/verification require Linux (WSL2 on Windows). "
            "No unsandboxed fallback is used."
        ),
    }


def _mib(value, divisor):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("Invalid process memory measurement")
    return round(value / divisor, 2)


def memory_snapshot():
    """Keep legacy field, but explicitly identify MiB, source and lifetime scope."""
    out = {
        "peak_rss_mb": None,
        "peak_rss_unit": "MiB",
        "rss_scope": "process peak unavailable; not an isolated scan peak",
        "rss_source": "unavailable",
    }
    try:
        if sys.platform == "win32":
            import psutil

            value = psutil.Process().memory_info().peak_wset
            out.update(peak_rss_mb=_mib(value, 1024**2), rss_source="psutil.peak_wset")
            out["rss_scope"] = "process peak working set, not isolated scan peak"
        else:
            import resource

            divisor = 1024**2 if sys.platform == "darwin" else 1024
            value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            out.update(peak_rss_mb=_mib(value, divisor), rss_source="resource.ru_maxrss")
            out["rss_scope"] = "process high-water mark, not isolated scan peak"
    except (ImportError, AttributeError, OSError, ValueError):
        # Telemetry must not make otherwise valid evidence unexportable.
        pass
    return out


def open_windows_regular(path):
    """Read a local disk file through a no-reparse Win32 handle, never a device.

    Parent reparse points, UNC/device paths and alternate streams are refused.
    A shared-read-only handle denies concurrent writes/deletion while inspected.
    This is file intake protection, not a Windows scanner/process sandbox.
    """
    if sys.platform != "win32":
        raise RuntimeError("Windows file adapter requires Windows")
    import ctypes
    from ctypes import wintypes
    import msvcrt

    raw = os.fspath(path)
    if not isinstance(raw, str) or raw.startswith(("\\\\", "//")):
        raise ValueError("Use a local disk path, not a UNC or device path")
    absolute = os.path.abspath(raw)
    drive, tail = os.path.splitdrive(absolute)
    if len(drive) != 2 or drive[1] != ":" or ":" in tail:
        raise ValueError("Alternate streams and non-drive paths are unsupported")
    for component in reversed(Path(absolute).parents):
        info = component.lstat()
        if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("Artifact parent reparse points are not allowed")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    kind = kernel.GetFileType
    kind.argtypes = [wintypes.HANDLE]
    kind.restype = wintypes.DWORD
    getinfo = kernel.GetFileInformationByHandleEx
    getinfo.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    getinfo.restype = wintypes.BOOL

    class AttributeTag(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]

    native = "\\\\?\\" + absolute if len(absolute) > 240 else absolute
    handle = create(native, 0x80000000, 1, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    fd = None
    try:
        attributes = AttributeTag()
        if kind(handle) != 1:  # FILE_TYPE_DISK only; no console or named pipe.
            raise ValueError("Artifact must be a local regular disk file")
        if not getinfo(handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        if attributes.attributes & (stat.FILE_ATTRIBUTE_REPARSE_POINT | stat.FILE_ATTRIBUTE_DIRECTORY):
            raise ValueError("Artifact must not be a reparse point or directory")
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None  # Ownership transferred to the CRT descriptor.
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Artifact must be a regular file")
        stream = os.fdopen(fd, "rb")
        fd = None
        return stream
    finally:
        if fd is not None:
            os.close(fd)
        if handle is not None:
            close(handle)
