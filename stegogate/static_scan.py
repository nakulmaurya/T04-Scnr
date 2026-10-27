"""Optional ModelAudit static-only adapter, isolated from the application process.

Reviewed interface: promptfoo/modelaudit cli.py scan options (2026-10-26).
Runtime help must also advertise every selected flag. Unreviewed scanner families
are never selected. Missing safety controls produce unavailable, not a pass.
"""

from __future__ import annotations
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from .intake import inspect_artifact, _limit, _unique, _bad_constant

# This bootstrap executes trusted installed scanner code, never uploaded code.
# Linux seccomp denies network and new processes for the scanner and all threads.
# Python imports of executable model frameworks/loaders are additionally refused.
_SANDBOX_SETUP = r"""
import os, sys, math, resource, ctypes, platform, importlib.abc, runpy
cpu, memory, artifact = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
args = sys.argv[4:]
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
# Guard unsafe deserialization functions even if scanner dependencies import them.
import pickle, _pickle

def refused(*a, **kw):
    raise RuntimeError('unsafe model deserialization disabled by T04-Scnr static adapter')
class RefusedUnpickler:
    def __init__(self, *a, **kw): refused()
for module in (pickle, _pickle):
    for name in ('load', 'loads'): setattr(module, name, refused)
    module.Unpickler = RefusedUnpickler
pickle._Unpickler = RefusedUnpickler
class FrameworkGuard(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'torch','tensorflow','keras','onnxruntime','joblib','dill','cloudpickle'}:
            raise ImportError('executable framework/loader disabled by static adapter')
sys.meta_path.insert(0, FrameworkGuard())
# Use a kernel-enforced no-network filter, not proxy environment promises.
if sys.platform != 'linux': raise RuntimeError('static sandbox requires Linux seccomp')
arch = platform.machine().lower()
if arch in ('x86_64', 'amd64'):
    audit_arch = 0xc000003e
    denied = [41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,288,299,307,322,435,425,426,427]
elif arch in ('aarch64', 'arm64'):
    audit_arch = 0xc00000b7
    denied = list(range(198,213)) + [220,221,243,269,281,435,425,426,427]
else: raise RuntimeError('unsupported seccomp architecture')
class Filter(ctypes.Structure):
    _fields_ = [('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint32)]
class Program(ctypes.Structure):
    _fields_ = [('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
# Verify syscall ABI, reject x32 syscalls, then return EPERM for network, process,
# and io_uring operations. Threads via clone are also denied intentionally.
ins = [(0x20,0,0,4),(0x15,1,0,audit_arch),(0x06,0,0,0x80000000),(0x20,0,0,0),
       (0x35,0,1,0x40000000),(0x06,0,0,0x80000000)]
for nr in denied: ins += [(0x15,0,1,nr),(0x06,0,0,0x00050001)]
ins += [(0x06,0,0,0x7fff0000)]
filters = (Filter * len(ins))(*(Filter(*v) for v in ins))
prog = Program(len(ins),filters)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(38,1,0,0,0) != 0 or libc.prctl(22,2,ctypes.byref(prog),0,0) != 0:
    raise RuntimeError('could not install mandatory seccomp filter')
# Defence in depth: refuse executable compilation/deserialization/native loading
# that refers to artifact path itself. Framework import guard stays active.
artifact_real = os.path.realpath(artifact)
def audit(event, args):
    if event in ('subprocess.Popen','os.system','os.exec','os.posix_spawn','pickle.find_class'):
        raise RuntimeError('execution/deserialization prohibited during static scan')
    if event in ('ctypes.dlopen', 'import') and args and isinstance(args[0], str) and os.path.realpath(args[0]) == artifact_real:
        raise RuntimeError('uploaded artifact cannot be imported or loaded')
sys.addaudithook(audit)
"""
_BOOTSTRAP = (
    _SANDBOX_SETUP + "sys.argv = ['modelaudit'] + args\nrunpy.run_module('modelaudit', run_name='__main__')\n"
)


def _kill(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait()


def _run_bounded(command, *, timeout, max_output, env, cwd):
    """Drain pipes incrementally; never communicate() an unbounded scanner stream."""
    started = time.monotonic()
    proc = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
        start_new_session=True,
        env=env,
        cwd=cwd,
    )
    sel = selectors.DefaultSelector()
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    state = None
    try:
        for pipe, label in [(proc.stdout, "stdout"), (proc.stderr, "stderr")]:
            os.set_blocking(pipe.fileno(), False)
            sel.register(pipe, selectors.EVENT_READ, label)
        while sel.get_map():
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                state = "timed_out"
                _kill(proc)
                break
            for key, _ in sel.select(min(remaining, 0.1)):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    sel.unregister(key.fileobj)
                    continue
                available = max_output - total
                streams[key.data].extend(block[: max(0, available)])
                total += len(block)
                if total > max_output:
                    state = "output_limit"
                    _kill(proc)
                    break
            if state:
                break
        if state is None:
            try:
                proc.wait(timeout=max(0.001, timeout - (time.monotonic() - started)))
            except subprocess.TimeoutExpired:
                state = "timed_out"
                _kill(proc)
    finally:
        sel.close()
        if proc.poll() is None:
            _kill(proc)
        proc.stdout.close()
        proc.stderr.close()
    return dict(
        state=state or "finished",
        returncode=proc.returncode,
        stdout=bytes(streams["stdout"]).decode("utf-8", "replace"),
        stderr=bytes(streams["stderr"]).decode("utf-8", "replace"),
    )


def _short(value, bound=2048):
    return str(value)[:bound] if value is not None else None


def _normalize(payload, returncode, max_findings=2000):
    if not isinstance(payload, dict):
        raise ValueError("scanner JSON must be an object")
    findings, seen, warnings = [], set(), []
    seen_base = set()
    issues, checks = payload.get("issues", []), payload.get("checks", [])
    if not isinstance(issues, list) or not isinstance(checks, list):
        raise ValueError("scanner issues/checks must be arrays")
    incomplete = payload.get("success") is False or bool(payload.get("errors"))
    skipped = 0
    for collection, kind in [(issues, "issue"), (checks, "check")]:
        for row in collection:
            if not isinstance(row, dict):
                incomplete = True
                continue
            state = str(row.get("status", "")).lower()
            if kind == "check" and state in ("skipped", "error", "unavailable", "inconclusive"):
                skipped += 1
                incomplete = True
            if kind == "check" and state not in ("failed", "fail"):
                continue
            detail = row.get("details") if isinstance(row.get("details"), dict) else {}
            # Operational failure is independent from severity/security findings.
            msg = _short(
                row.get("message")
                or row.get("description")
                or row.get("name")
                or row.get("check_name")
                or "Unnamed scanner finding"
            )
            if any(
                s in (msg or "").lower()
                for s in (
                    "could not scan",
                    "unable to scan",
                    "scan failed",
                    "dependency unavailable",
                    "inconclusive",
                    "timed out",
                    "scan timeout",
                )
            ):
                incomplete = True
            severity = _short(row.get("severity", "unknown"), 64)
            finding = dict(
                source="modelaudit",
                kind=kind,
                severity=severity,
                message=msg,
                location=_short(row.get("location")),
                rule_code=_short(row.get("rule_code") or row.get("code"), 128),
            )
            if "original_severity" in detail:
                finding["original_severity"] = _short(detail["original_severity"], 64)
            if detail.get("scan_outcome") not in (None, "completed", "success"):
                incomplete = True
            base_identity = (severity.lower() if severity else severity, msg, finding["location"])
            # ModelAudit commonly mirrors an issue as a failed check without a
            # rule code. Do not double-count that same indicator.
            if kind == "check" and base_identity in seen_base:
                continue
            identity = (severity, msg, finding["location"], finding["rule_code"])
            if identity not in seen:
                seen.add(identity)
                seen_base.add(base_identity)
                if len(findings) < max_findings:
                    findings.append(finding)
                else:
                    incomplete = True
    metadata = payload.get("metadata")
    if isinstance(metadata, dict) and metadata.get("scan_outcome") not in (None, "completed", "success"):
        incomplete = True
    scanned = payload.get("files_scanned")
    # Completion must be evidenced in structured output, not inferred from rc=0.
    completed = type(scanned) is int and scanned > 0 and payload.get("success") is True
    if not completed:
        incomplete = True
    if returncode not in (0, 1):
        incomplete = True
    if skipped:
        warnings.append(f"{skipped} scanner checks were skipped/unavailable/inconclusive.")
    if len(seen) > max_findings:
        warnings.append("Findings truncated at configured bounded limit.")
    if incomplete:
        warnings.append("Scanner output did not establish complete static coverage; findings may be partial.")
    return ("partial" if incomplete else "completed"), findings, warnings


def run_modelaudit(path: str | Path, config: dict | None = None) -> dict:
    start = time.monotonic()
    out = dict(status="unavailable", findings=[], engine_version=None, warnings=[], duration_seconds=0.0)
    try:
        seconds = _limit(config, "static_timeout_seconds", 30, 300)
        max_output = _limit(config, "static_max_output_bytes", 2 * 1024**2, 8 * 1024**2)
        memory = _limit(config, "static_memory_mb", 2048, 8192) * 1024**2
        max_findings = _limit(config, "static_max_findings", 2000, 10000)
        inventory = inspect_artifact(path, config)
        if inventory["errors"]:
            out["status"] = "failed"
            out["warnings"] += inventory["errors"]
            return out
        out["artifact_sha256"] = inventory["sha256"]
        scanner = {"safetensors": "safetensors", "pytorch_zip": "pytorch_zip", "pickle": "pickle"}.get(
            inventory["format"]
        )
        if scanner is None:
            out["warnings"].append("No reviewed static scanner for this unknown format.")
            return out
        if sys.platform != "linux":
            out["warnings"].append("Mandatory network-blocking sandbox requires Linux.")
            return out
        if importlib.util.find_spec("modelaudit") is None:
            out["warnings"].append(
                "Optional ModelAudit package is not installed; no static scan was performed."
            )
            return out
        try:
            out["engine_version"] = importlib.metadata.version("modelaudit")
        except importlib.metadata.PackageNotFoundError:
            pass
        absolute = str(Path(path).resolve(strict=True))
        # Environment is deliberately allowlisted: no cloud credentials, tokens,
        # scanner settings, PYTHONPATH, user config, or GPU devices are inherited.
        with tempfile.TemporaryDirectory(prefix="stegogate-static-") as temp:
            env = dict(
                PATH=os.defpath,
                HOME=temp,
                TMPDIR=temp,
                XDG_CONFIG_HOME=temp,
                XDG_CACHE_HOME=temp,
                CUDA_VISIBLE_DEVICES="",
                NVIDIA_VISIBLE_DEVICES="none",
                OMP_NUM_THREADS="1",
                OPENBLAS_NUM_THREADS="1",
                MKL_NUM_THREADS="1",
                NUMEXPR_NUM_THREADS="1",
                HF_HUB_OFFLINE="1",
                TRANSFORMERS_OFFLINE="1",
                NO_COLOR="1",
                CI="1",
                DO_NOT_TRACK="1",
                PYTHONNOUSERSITE="1",
            )
            base = [sys.executable, "-I", "-c", _BOOTSTRAP, str(seconds), str(memory), absolute]
            deadline = time.monotonic() + seconds
            help_result = _run_bounded(
                base + ["scan", "--help"],
                timeout=min(8, seconds),
                max_output=min(max_output, 128 * 1024),
                env=env,
                cwd=temp,
            )
            if help_result["state"] == "timed_out":
                out["status"] = "timed_out"
                out["warnings"].append("Scanner CLI capability check timed out.")
                return out
            help_text = help_result["stdout"]
            required = ["--format", "--no-cache", "--no-whitelist", "--scanners", "--timeout", "--max-size"]
            if (
                help_result["state"] != "finished"
                or help_result["returncode"] != 0
                or not all(flag in help_text for flag in required)
            ):
                out["warnings"].append(
                    "Installed ModelAudit CLI lacks verified safety/selection options or sandbox could not start."
                )
                out["warnings"].append(
                    _short(help_result["stderr"], 1000) or "No compatible CLI help returned."
                )
                return out
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                out["status"] = "timed_out"
                return out
            # Fixed allowlisted arguments. No unsafe opt-in, inference, metadata
            # extraction, custom code, URLs, shell, whitelist, or download flags.
            command = base + [
                "scan",
                "--format",
                "json",
                "--no-cache",
                "--no-whitelist",
                "--scanners",
                scanner,
                "--timeout",
                str(max(1, int(remaining))),
                "--max-size",
                str(inventory["size_bytes"] + 1),
                "--",
                absolute,
            ]
            result = _run_bounded(command, timeout=remaining, max_output=max_output, env=env, cwd=temp)
            if result["state"] == "timed_out":
                out["status"] = "timed_out"
                out["warnings"].append("Static scanner exceeded wall-clock timeout; no completion claim.")
                return out
            if result["state"] == "output_limit":
                out["status"] = "partial"
                out["warnings"].append(
                    "Static scanner output limit exceeded; process terminated, findings not parsed."
                )
                return out
            payload = json.loads(result["stdout"], object_pairs_hook=_unique, parse_constant=_bad_constant)
            out["status"], out["findings"], warnings = _normalize(payload, result["returncode"], max_findings)
            out["warnings"].extend(warnings)
            if result["stderr"].strip():
                out["warnings"].append("Scanner diagnostics (bounded): " + result["stderr"][:1000])
            final = inspect_artifact(path, config)
            if final["errors"] or final["sha256"] != inventory["sha256"]:
                out.update(status="failed", findings=[])
                out["warnings"].append(
                    "Artifact identity changed during static scan; scanner findings discarded."
                )
    except (OSError, ValueError, TypeError, RecursionError, OverflowError, ImportError) as e:
        out["status"] = "failed"
        out["warnings"].append(f"{type(e).__name__}: {str(e)[:500]}")
    finally:
        out["duration_seconds"] = max(0.0, time.monotonic() - start)
    return out
