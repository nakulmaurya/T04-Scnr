"""Bounded, non-executing artifact inventory. No tensor framework is imported."""

from __future__ import annotations
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import struct
import sys

DEFAULT_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_HEADER_BYTES = 8 * 1024 * 1024
DTYPE_BYTES = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "U16": 2,
    "I16": 2,
    "F16": 2,
    "BF16": 2,
    "U32": 4,
    "I32": 4,
    "F32": 4,
    "U64": 8,
    "I64": 8,
    "F64": 8,
    "F8_E4M3": 1,
    "F8_E5M2": 1,
    "F8_E4M3FN": 1,
    "F8_E8M0": 1,
    "F8_E4M3FNUZ": 1,
    "F8_E5M2FNUZ": 1,
    "C64": 8,
}


def _limit(config, name, default, hard_max=None):
    value = (config or {}).get(name, default)
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    if hard_max is not None and value > hard_max:
        raise ValueError(f"{name} exceeds hard safety bound {hard_max}")
    return value


def _open_regular(path):
    """Refuse symlinks/devices/FIFOs before any blocking reads."""
    if sys.platform == "win32":
        from .platform_support import open_windows_regular

        return open_windows_regular(path)
    fd = os.open(os.fspath(path), os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("artifact must be a regular, non-symlink file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _snapshot(f):
    s = os.fstat(f.fileno())
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate JSON key")
        result[k] = v
    return result


def _bad_constant(value):
    raise ValueError("non-standard JSON numeric constant")


def inspect_artifact(path: str | Path, config: dict | None = None) -> dict:
    out = dict(format="unknown", size_bytes=0, sha256="", tensors=[], metadata={}, errors=[], warnings=[])
    try:
        max_file = _limit(config, "max_artifact_bytes", DEFAULT_MAX_ARTIFACT_BYTES, 4 * 1024**3)
        max_header = _limit(config, "max_header_bytes", DEFAULT_MAX_HEADER_BYTES, 64 * 1024**2)
        max_tensors = _limit(config, "max_tensors", 100_000, 200_000)
        max_dims = _limit(config, "max_dimensions", 32, 64)
        max_numel = _limit(config, "max_tensor_numel", 1 << 40, 1 << 48)
        max_name = _limit(config, "max_tensor_name_bytes", 1024, 8192)
        with _open_regular(path) as f:
            before = _snapshot(f)
            size = before[2]
            out["size_bytes"] = size
            if size > max_file:
                raise ValueError("artifact exceeds max_artifact_bytes; not hashed or parsed")
            h = hashlib.sha256()
            remaining = size
            while remaining:
                block = f.read(min(1024 * 1024, remaining))
                if not block:
                    raise ValueError("artifact truncated while hashing")
                h.update(block)
                remaining -= len(block)
            if f.read(1) or before != _snapshot(f):
                raise ValueError("artifact changed while hashing")
            out["sha256"] = h.hexdigest()
            f.seek(0)
            prefix = f.read(8)
            intended = str(path).lower().endswith(".safetensors")
            if not intended and prefix.startswith(b"PK\x03\x04"):
                out["format"] = "pytorch_zip"
                out["warnings"].append(
                    "ZIP signature only; archive not deserialized or validated as PyTorch."
                )
                return out
            if not intended and (
                prefix[:1] == b"\x80" or str(path).lower().endswith((".pkl", ".pickle", ".pt", ".pth"))
            ):
                out["format"] = "pickle" if prefix[:1] == b"\x80" else "unknown"
                out["warnings"].append(
                    "Unsupported serialization: not deserialized. File extension is not proof of format."
                )
                return out
            header_len = struct.unpack("<Q", prefix)[0] if len(prefix) == 8 else 0
            # A small plausible length is the only content-based safetensors probe.
            if not intended and not (2 <= header_len <= max_header and header_len <= size - 8):
                out["warnings"].append("Unknown or unsupported format; not weight-analyzed.")
                return out
            out["format"] = "safetensors"
            if len(prefix) != 8 or not 2 <= header_len <= max_header or header_len > size - 8:
                raise ValueError("invalid or excessive safetensors header length")
            raw = f.read(header_len)
            if len(raw) != header_len or not raw.startswith(b"{"):
                raise ValueError("safetensors header must start with JSON object")
            text = raw.decode("utf-8", errors="strict")
            decoder = json.JSONDecoder(object_pairs_hook=_unique, parse_constant=_bad_constant)
            header, end = decoder.raw_decode(text)
            if text[end:].strip(" ") != "":
                raise ValueError("header padding must contain only spaces")
            if not isinstance(header, dict):
                raise ValueError("header must be an object")
            if len(header) > max_tensors + (1 if "__metadata__" in header else 0):
                raise ValueError("too many tensors")
            metadata = header.pop("__metadata__", {})
            if not isinstance(metadata, dict) or any(
                not isinstance(k, str) or not isinstance(v, str) for k, v in metadata.items()
            ):
                raise ValueError("__metadata__ must map strings to strings")
            for key, value in metadata.items():
                key.encode("utf-8", errors="strict")
                value.encode("utf-8", errors="strict")
            data_bytes = size - 8 - header_len
            tensors = []
            for name, info in header.items():
                if not isinstance(name, str) or len(name.encode("utf-8")) > max_name:
                    raise ValueError("tensor name exceeds bound")
                if not isinstance(info, dict) or set(info) != {"dtype", "shape", "data_offsets"}:
                    raise ValueError("tensor record requires exactly dtype, shape, data_offsets")
                dtype, shape, offsets = info["dtype"], info["shape"], info["data_offsets"]
                if not isinstance(dtype, str) or dtype not in DTYPE_BYTES:
                    raise ValueError("unsupported or invalid safetensors dtype")
                if (
                    not isinstance(shape, list)
                    or len(shape) > max_dims
                    or any(type(d) is not int or d < 0 or d > max_numel for d in shape)
                ):
                    raise ValueError("invalid tensor shape")
                # Bound nonzero product even when a zero axis could mask huge dimensions.
                nonzero_product = math.prod(d for d in shape if d != 0)
                if nonzero_product > max_numel:
                    raise ValueError("tensor shape product exceeds bound")
                numel = math.prod(shape)
                nbytes = numel * DTYPE_BYTES[dtype]
                if (
                    not isinstance(offsets, list)
                    or len(offsets) != 2
                    or any(type(o) is not int for o in offsets)
                ):
                    raise ValueError("invalid data_offsets")
                start, stop = offsets
                if not 0 <= start <= stop <= data_bytes or stop - start != nbytes:
                    raise ValueError("tensor offsets out of bounds or shape/byte-size mismatch")
                tensors.append(
                    dict(
                        name=name, dtype=dtype, shape=shape, data_offsets=offsets, numel=numel, nbytes=nbytes
                    )
                )
            # Empty tensors consume no bytes but must lie at a real boundary, never
            # inside another tensor. Tie-break empty intervals before nonempty ones.
            cursor = 0
            for t in sorted(tensors, key=lambda t: (t["data_offsets"][0], t["data_offsets"][1])):
                start, stop = t["data_offsets"]
                if start != cursor:
                    raise ValueError("tensor data contains overlap, gap, or misplaced empty tensor")
                cursor = stop
            if cursor != data_bytes:
                raise ValueError("unclaimed trailing data or missing tensors")
            if before != _snapshot(f):
                raise ValueError("artifact changed while parsing")
            out.update(tensors=tensors, metadata=metadata, header_bytes=header_len, data_start=8 + header_len)
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, struct.error) as e:
        out["errors"].append(f"{type(e).__name__}: {str(e)[:300]}")
        out["tensors"] = []
        out["metadata"] = {}
    return out
