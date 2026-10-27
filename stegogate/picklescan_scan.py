"""Hash-linked Picklescan 1.0.5 disassembly, never pickle deserialization.

Only a bounded raw pickle or .pkl ZIP member is passed to the reviewed library.
Archive extraction, nested formats, directory walking and URL helpers are unused.
"""

from __future__ import annotations
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from .intake import inspect_artifact
from .static_scan import _SANDBOX_SETUP, _run_bounded

# Trusted installed package code runs under the same mandatory kernel restrictions.
_WORKER = (
    _SANDBOX_SETUP
    + r"""
import io, json, pickletools, zipfile
from pathlib import PurePosixPath
from picklescan.scanner import scan_pickle_bytes
MAX_MEMBER = 16*1024*1024
MAX_TOTAL = 32*1024*1024
findings, warnings = [], []
scanned = 0
opcodes = 0

def examine(raw, member):
    global scanned, opcodes
    stream = io.BytesIO(raw)
    try:
        while stream.tell() < len(raw):
            stopped = False
            for op, arg, pos in pickletools.genops(stream):
                opcodes += 1
                if opcodes > 250000: raise ValueError('opcode budget exceeded')
                if op.name == 'STOP': stopped = True
            if not stopped: raise ValueError('missing STOP')
    except Exception:
        warnings.append('Invalid or over-budget pickle syntax; no clean conclusion.')
        # Do not call library on over-budget input; it materializes opcode lists.
        return
    result = scan_pickle_bytes(io.BytesIO(raw), member)
    scanned += result.scanned_files
    if result.scan_err: warnings.append('Picklescan reported incomplete parsing.')
    for item in result.globals:
        level = item.safety.name
        if level not in ('Dangerous', 'Suspicious'): continue
        if len(findings) >= 200:
            warnings.append('Finding limit reached.'); break
        findings.append(dict(rule='PICKLESCAN_'+level.upper()+'_GLOBAL',
            severity='high' if level == 'Dangerous' else 'medium',
            module=str(item.module)[:200], name=str(item.name)[:200],
            member=member[:200], message='Referenced global; not evidence of payload execution.'))

with open(artifact, 'rb') as f:
    signature = f.read(4); f.seek(0)
    if signature.startswith(b'PK'):
        with zipfile.ZipFile(f) as z:
            entries = z.infolist()
            if len(entries)>4096: raise ValueError('ZIP entry budget exceeded')
            names = set(); total = 0
            for entry in entries:
                name = entry.filename
                parts = PurePosixPath(name).parts
                if name in names or '\\' in name or name.startswith('/') or '..' in parts:
                    raise ValueError('unsafe or duplicate ZIP member')
                names.add(name)
                if not name.endswith('.pkl'): continue
                if entry.flag_bits & 1: raise ValueError('encrypted member')
                total += entry.file_size
                if entry.file_size>MAX_MEMBER or total>MAX_TOTAL or entry.file_size>200*max(1,entry.compress_size):
                    raise ValueError('ZIP size or compression budget exceeded')
                with z.open(entry) as src: raw = src.read(MAX_MEMBER+1)
                if len(raw)!=entry.file_size: raise ValueError('member length mismatch')
                examine(raw, name)
    else:
        raw = f.read(MAX_MEMBER+1)
        if len(raw)>MAX_MEMBER: raise ValueError('raw pickle exceeds budget')
        examine(raw, 'artifact')
if not scanned: warnings.append('No supported pickle stream was completely inspected.')
print(json.dumps(dict(status='partial' if warnings else 'completed', findings=findings,
    scanned_files=scanned, warnings=warnings), allow_nan=False))
"""
)


def run_picklescan(path, config=None):
    started = time.monotonic()
    out = dict(status="unavailable", engine_version=None, findings=[], warnings=[], duration_seconds=0.0)
    try:
        inv = inspect_artifact(path, config)
        if inv["errors"]:
            out["warnings"] = ["Invalid artifact; scanner not run."]
            return out
        if inv["format"] == "safetensors":
            out["status"] = "not_applicable"
            return out
        if inv["format"] not in ("pickle", "pytorch_zip"):
            out["warnings"] = ["Only binary pickle and pickle-bearing ZIP are reviewed."]
            return out
        if sys.platform != "linux":
            out["warnings"] = ["Mandatory Linux seccomp is unavailable."]
            return out
        try:
            version = importlib.metadata.version("picklescan")
        except importlib.metadata.PackageNotFoundError:
            out["warnings"] = ["Optional Picklescan is not installed."]
            return out
        out["engine_version"] = version
        if version != "1.0.5":
            out["warnings"] = ["Unreviewed Picklescan version; refusing scan."]
            return out
        seconds = int((config or {}).get("static_timeout_seconds", 60))
        if not 1 <= seconds <= 180:
            raise ValueError("invalid timeout")
        with tempfile.TemporaryDirectory(prefix="stegogate-picklescan-") as tmp:
            env = dict(
                PATH=os.defpath,
                HOME=tmp,
                TMPDIR=tmp,
                CUDA_VISIBLE_DEVICES="",
                NVIDIA_VISIBLE_DEVICES="none",
                PYTHONNOUSERSITE="1",
                OMP_NUM_THREADS="1",
            )
            result = _run_bounded(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    _WORKER,
                    str(seconds),
                    str(1024**3),
                    str(Path(path).resolve(strict=True)),
                ],
                timeout=seconds,
                max_output=128 * 1024,
                env=env,
                cwd=tmp,
            )
        if result["state"] != "finished" or result["returncode"] != 0:
            out["status"] = "timed_out" if result["state"] == "timed_out" else "failed"
            out["warnings"] = ["Isolated disassembly failed or exceeded a resource budget."]
            return out
        payload = json.loads(result["stdout"])
        if payload.get("status") not in ("completed", "partial") or not isinstance(
            payload.get("findings"), list
        ):
            raise ValueError("invalid worker report")
        if len(payload["findings"]) > 200:
            raise ValueError("unbounded findings")
        out.update(payload)
        after = inspect_artifact(path, config)
        if after["errors"] or after["sha256"] != inv["sha256"]:
            out.update(status="failed", findings=[], warnings=["Artifact changed during scan."])
        out["artifact_sha256"] = inv["sha256"]
    except Exception:
        out.update(status="failed", warnings=["Picklescan adapter failed closed."])
    finally:
        out["duration_seconds"] = round(time.monotonic() - started, 4)
    return out
