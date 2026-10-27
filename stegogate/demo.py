"""Explicit, pinned research demos. Never imported torch on the default scan path.

Only the preparation subprocess can deserialize the two publisher checkpoints.
Downloaded Python source is reviewed as text, never imported or executed.
"""

from __future__ import annotations
import argparse
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import socket
import selectors
import signal
import struct
import subprocess
import sys
import time
import urllib.request

_MNIST_REV = "42b52757ec703365710e27865c8fe57e9db35a4d"
_CIFAR_REV = "b68ac7c29824b0eef7d38176eb5e19cfde20c4c6"
_CATALOG = {
    "mnist-epoch01": {
        "title": "MNIST preceding checkpoint (epoch 1)",
        "repository": "authentrics/mnist-badnets-poisoned",
        "revision": _MNIST_REV,
        "filename": "epoch_01.pt",
        "size_bytes": 250453,
        "sha256": "6c0b5fe0c5f794678020292d2184b84029527e3fff86a62a3571dacb75ae117d",
        "license": "Apache-2.0",
        "author_metrics": {"clean_accuracy": 0.9431, "shifted_label_attack_success": 0.0041},
        "role": "preceding_checkpoint_not_pristine_final_control",
    },
    "mnist-epoch02": {
        "title": "MNIST poisoned checkpoint (epoch 2)",
        "repository": "authentrics/mnist-badnets-poisoned",
        "revision": _MNIST_REV,
        "filename": "epoch_02.pt",
        "size_bytes": 250453,
        "sha256": "ded215b9d3583d7e386e47680345b5be32a8400fe190cb6fb758b4dca8a092db",
        "license": "Apache-2.0",
        "author_metrics": {"clean_accuracy": 0.9664, "shifted_label_attack_success": 0.9489},
        "role": "publisher_poisoned_checkpoint",
    },
    "cifar10-resnet18": {
        "title": "CIFAR-10 BadNets ResNet-18",
        "repository": "hugo0076/cifar10-badnets-backdoor-resnet18",
        "revision": _CIFAR_REV,
        "filename": "model.safetensors",
        "size_bytes": 44780752,
        "sha256": "f8389e3312359d4db7d6cbd7a999e3bc9213092d7abb2ce002f3ea88fc79e161",
        "license": "MIT declared; inherited microsoft/resnet-18 license must also be reviewed",
        "author_metrics": {
            "clean_accuracy": 0.814,
            "target_class_attack_success": 0.819,
            "sample_count": 10000,
        },
        "role": "trigger_geometry_not_documented",
    },
}
_DATA = {
    "t10k-images-idx3-ubyte.gz": (
        1648877,
        "8d422c7b0a1c1c79245a5bcf07fe86e33eeafee792b84584aec276f5a2dbc4e6",
    ),
    "t10k-labels-idx1-ubyte.gz": (4542, "f7ae60f92e00ec6debd23a6088c31dbd2371eca3ffa0defaefb259924204aec6"),
}
_CONVERTED_HASHES = {
    "mnist-epoch01": "88ebce334a81ad59fe59dc809165f25ba2ff3520bfd3701ba644dfe1720a78bf",
    "mnist-epoch02": "6d33d1dcfe4a81ad0b0636bec59e724b748c6e9b61db1d6e2d0c67e090da8d19",
}


def get_demo_catalog() -> list[dict]:
    """Return metadata only; no filesystem reads, imports, network, or inference."""
    return [
        dict(
            copy.deepcopy(v),
            demo_id=k,
            id=k,
            prepared_filename="model.safetensors",
            artifact_relative_path=k + "/model.safetensors",
            manifest_relative_path=k + "/manifest.json",
            verification_relative_path=k + "/verification.json",
            behavioral_status="not_verified",
        )
        for k, v in _CATALOG.items()
    ]


def _entry(demo_id):
    if not isinstance(demo_id, str) or demo_id not in _CATALOG:
        raise ValueError("Unknown demo ID; only fixed catalog IDs are allowed")
    return _CATALOG[demo_id]


def _file(root, *parts):
    if any(
        not isinstance(part, str) or part in ("", ".", "..") or "/" in part or "\\" in part for part in parts
    ):
        raise ValueError("Only fixed single-component demo paths are allowed")
    root = Path(root).expanduser().absolute()
    # Reject symlink roots/parents too, rather than allowing an alias outside configured data.
    for p in (root, *root.parents):
        if p.is_symlink():
            raise ValueError("Symlink demo root is not allowed")
    target = root.joinpath(*parts)
    for p in (target, *target.parents):
        if p == root.parent:
            break
        if p.is_symlink():
            raise ValueError("Symlink demo paths are not allowed")
    if not target.is_relative_to(root):
        raise ValueError("Demo path escaped root")
    return target


def _sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def _check(path, size, digest):
    if not path.is_file() or path.stat().st_size != size or _sha(path) != digest:
        raise ValueError("Pinned artifact size/SHA256 mismatch: " + path.name)


def _download(url, path, size, digest):
    if path.exists():
        _check(path, size, digest)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".download")
    if tmp.is_symlink():
        raise ValueError("Symlink temporary file rejected")
    if tmp.exists():
        raise ValueError("Stale download temporary file; remove explicitly")
    try:
        # Fixed HTTPS sources only; no credentials, SDK, or user URLs.
        with urllib.request.urlopen(url, timeout=60) as r, tmp.open("xb") as f:
            total = 0
            while chunk := r.read(1024 * 1024):
                total += len(chunk)
                if total > size:
                    raise ValueError("Download exceeds pinned size")
                f.write(chunk)
        _check(tmp, size, digest)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _atomic_json(path, value):
    tmp = path.with_suffix(".json.tmp")
    if tmp.is_symlink():
        raise ValueError("Symlink temporary file rejected")
    with tmp.open("x") as f:
        json.dump(value, f, indent=2, allow_nan=False)
    os.replace(tmp, path)


def _optin(config):
    if not config or config.get("opt_in") is not True:
        raise ValueError("Explicit config opt_in=True is required")


def _kill_worker_group(proc):
    """Kill the isolated session, including descendants retaining pipe handles."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _run_bounded(command, env, timeout):
    """Drain both pipes with a shared 64 KiB allocation budget and wall deadline."""
    limit = 65536
    output = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    deadline = time.monotonic() + timeout
    proc = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        shell=False,
        start_new_session=True,
        bufsize=0,
    )
    state = "completed"
    try:
        with selectors.DefaultSelector() as selector:
            for name, pipe in [("stdout", proc.stdout), ("stderr", proc.stderr)]:
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map() or proc.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    state = "timed_out"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    try:
                        chunk = os.read(key.fileobj.fileno(), min(4096, limit - total + 1))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if total + len(chunk) > limit:
                        state = "output_limit"
                        break
                    output[key.data].extend(chunk)
                    total += len(chunk)
                if state != "completed":
                    break
    finally:
        # Also kill descendants on ordinary completion; no orphan workers survive.
        _kill_worker_group(proc)
        for pipe in (proc.stdout, proc.stderr):
            pipe.close()
    return state, bytes(output["stdout"]), bytes(output["stderr"]), proc.returncode


def _subprocess(action, demo_id, root, config):
    if sys.platform != "linux":
        return {
            "status": "unavailable",
            "warnings": [
                "Isolated demo preparation/verification requires Linux; use WSL2 on Windows. No worker was started."
            ],
        }
    timeout = min(max(float(config.get("timeout_seconds", 180)), 1), 600)
    command = [
        sys.executable,
        "-I",
        str(Path(__file__).resolve()),
        "--worker",
        action,
        "--demo-id",
        demo_id,
        "--root",
        str(Path(root).absolute()),
        "--samples",
        str(int(config.get("sample_count", 10000))),
    ]
    env = {
        k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "LD_LIBRARY_PATH", "SYSTEMROOT")
    }
    env.update(
        {
            "OMP_NUM_THREADS": "2",
            "MKL_NUM_THREADS": "2",
            "OPENBLAS_NUM_THREADS": "2",
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "CUDA_VISIBLE_DEVICES": "",
        }
    )
    try:
        state, stdout, stderr, returncode = _run_bounded(command, env, timeout)
    except OSError as e:
        return {"status": "failed", "warnings": ["Unable to start isolated demo worker: " + str(e)[:500]]}
    if state == "timed_out":
        return {
            "status": "timed_out",
            "warnings": ["Isolated demo worker exceeded deadline; process group killed"],
        }
    if state == "output_limit":
        return {
            "status": "failed",
            "warnings": ["Worker combined stdout/stderr exceeded 64 KiB; process group killed"],
        }
    if returncode != 0:
        return {
            "status": "failed",
            "warnings": [
                "Worker exited abnormally: " + str(returncode),
                stderr[-1500:].decode("utf-8", errors="replace"),
            ],
        }
    try:
        result = json.loads(stdout)
        if not isinstance(result, dict):
            raise ValueError("Expected JSON object")
    except (ValueError, TypeError):
        return {
            "status": "failed",
            "warnings": [
                "Worker failed without a valid JSON result",
                stderr[-1500:].decode("utf-8", errors="replace"),
            ],
        }
    return result


def prepare_demo(demo_id: str, root: Path, config=None) -> dict:
    """Explicit online acquisition + isolated restricted conversion. Root is demo dir."""
    e = _entry(demo_id)
    _optin(config)
    if sys.platform != "linux":
        return {
            "status": "unavailable",
            "demo_id": demo_id,
            "warnings": [
                "Demo preparation requires Linux isolation; use WSL2 on Windows. Nothing was downloaded or executed."
            ],
        }
    started = time.monotonic()
    source = _file(root, demo_id, e["filename"])
    _download(
        f"https://huggingface.co/{e['repository']}/resolve/{e['revision']}/{e['filename']}",
        source,
        e["size_bytes"],
        e["sha256"],
    )
    if config.get("download_test_data") and demo_id.startswith("mnist-"):
        for name, (size, digest) in _DATA.items():
            _download(
                "https://ossci-datasets.s3.amazonaws.com/mnist/" + name,
                _file(root, "mnist-test", name),
                size,
                digest,
            )
    result = _subprocess("prepare", demo_id, root, config)
    result.update(
        {
            "demo_id": demo_id,
            "duration_seconds": time.monotonic() - started,
            "source_sha256": e["sha256"],
            "source_revision": e["revision"],
        }
    )
    return result


def verify_behavior(demo_id: str, root: Path, config=None) -> dict:
    """CPU-only, offline opt-in worker. Never deserialize publisher .pt here."""
    _entry(demo_id)
    _optin(config)
    n = int(config.get("sample_count", 10000))
    if not 1 <= n <= 10000:
        raise ValueError("sample_count must be 1..10000")
    return _subprocess("verify", demo_id, root, config)


def _no_network():
    def denied(*a, **k):
        raise RuntimeError("Network disabled in demo worker")

    socket.socket.connect = denied
    socket.socket.connect_ex = denied
    socket.socket.sendto = denied
    if hasattr(socket.socket, "sendmsg"):
        socket.socket.sendmsg = denied
    socket.create_connection = denied
    socket.getaddrinfo = denied
    # Defense in depth at Python application layer, not an OS sandbox claim.


def _model():
    # Original implementation of the reviewed tensor topology. No source imports.
    import torch.nn as nn

    class ReviewedLeNet(nn.Module):
        def __init__(self):
            super().__init__()
            self.convnet = nn.Sequential(
                nn.Conv2d(1, 6, 1),
                nn.ReLU(),
                nn.MaxPool2d(2),
                nn.Conv2d(6, 16, 5),
                nn.ReLU(),
                nn.MaxPool2d(2),
                nn.Conv2d(16, 120, 5),
                nn.ReLU(),
            )
            self.fc = nn.Sequential(nn.Linear(120, 84), nn.ReLU(), nn.Linear(84, 10), nn.LogSoftmax(dim=-1))

        def forward(self, x):
            return self.fc(self.convnet(x).flatten(1))

    return ReviewedLeNet()


def _validate_state(state, model, require_f32=True):
    import torch
    from collections import OrderedDict

    if type(state) not in (dict, OrderedDict):
        raise ValueError("Checkpoint must contain only a plain tensor state dictionary")
    expected = model.state_dict()
    if set(state) != set(expected):
        raise ValueError("Unexpected state dictionary keys")
    for key, t in state.items():
        if type(key) is not str or type(t) is not torch.Tensor:
            raise ValueError("Custom objects and tensor subclasses rejected")
        if t.layout != torch.strided or tuple(t.shape) != tuple(expected[key].shape):
            raise ValueError("Invalid tensor layout or shape")
        if require_f32 and t.dtype != torch.float32:
            raise ValueError("Expected F32 tensor")
        if t.dtype != expected[key].dtype:
            raise ValueError("Unexpected tensor dtype")
        if t.dtype.is_floating_point and not torch.isfinite(t).all().item():
            raise ValueError("Nonfinite weights rejected")
    model.load_state_dict(state, strict=True)


def _resnet():
    # Trusted installed transformers classes only, no Auto class or remote code.
    from transformers import ResNetConfig, ResNetForImageClassification

    return ResNetForImageClassification(
        ResNetConfig(
            depths=[2, 2, 2, 2],
            hidden_sizes=[64, 128, 256, 512],
            embedding_size=64,
            num_channels=3,
            num_labels=10,
            layer_type="basic",
            hidden_act="relu",
            downsample_in_first_stage=False,
            downsample_in_bottleneck=False,
        )
    )


def _prepare_worker(demo_id, root):
    import torch

    torch.set_num_threads(2)
    from safetensors.torch import load_file, save_file

    e = _entry(demo_id)
    src = _file(root, demo_id, e["filename"])
    _check(src, e["size_bytes"], e["sha256"])
    out = _file(root, demo_id, "model.safetensors")
    architecture_status = "validated"
    if demo_id.startswith("mnist-"):
        model = _model()
        # THIS IS THE ONLY PICKLE-CAPABLE CALL; fixed pinned input, preparation only.
        # Never add safe globals, fallback loaders, or weights_only=False.
        state = torch.load(src, map_location="cpu", weights_only=True)
        _validate_state(state, model)
        tmp = _file(root, demo_id, "model.safetensors.converting")
        if tmp.exists():
            raise ValueError("Stale conversion temporary file; remove explicitly")
        save_file({k: v.detach().cpu().contiguous() for k, v in sorted(state.items())}, str(tmp))
        _validate_state(load_file(str(tmp), device="cpu"), model)
        if demo_id in _CONVERTED_HASHES and _sha(tmp) != _CONVERTED_HASHES[demo_id]:
            tmp.unlink()
            raise ValueError("Converted artifact hash differs from pinned export")
        os.replace(tmp, out)
    else:
        state = load_file(str(out), device="cpu")
        if not state:
            raise ValueError("Empty ResNet state")
        for key, t in state.items():
            if t.dtype == torch.float32:
                if not torch.isfinite(t).all():
                    raise ValueError("Nonfinite ResNet weight")
            elif not (key.endswith(".num_batches_tracked") and t.dtype == torch.int64 and t.ndim == 0):
                raise ValueError("Expected F32 weights or I64 scalar batch counters")
        try:
            _validate_state(state, _resnet(), require_f32=False)
        except ImportError:
            architecture_status = "unavailable_transformers"
    result = {
        "status": "completed",
        "demo_id": demo_id,
        "artifact_path": str(out),
        "sha256": _sha(out),
        "size_bytes": out.stat().st_size,
        "source_sha256": e["sha256"],
        "source_revision": e["revision"],
        "architecture_status": architecture_status,
        "tensor_count": len(state),
        "behavioral_status": "not_verified",
    }
    _atomic_json(_file(root, demo_id, "manifest.json"), result)
    return result


def _prepared(demo_id, root):
    e = _entry(demo_id)
    f = _file(root, demo_id, "model.safetensors")
    p = _file(root, demo_id, "manifest.json")
    if not p.is_file() or p.stat().st_size > 16384:
        raise ValueError("Missing/invalid preparation manifest")
    meta = json.loads(p.read_text(encoding="utf-8"))
    if (
        meta.get("demo_id") != demo_id
        or meta.get("source_sha256") != e["sha256"]
        or meta.get("source_revision") != e["revision"]
    ):
        raise ValueError("Preparation manifest provenance mismatch")
    expected = e["sha256"] if demo_id == "cifar10-resnet18" else _CONVERTED_HASHES.get(demo_id)
    if not expected:
        raise ValueError("No pinned converted export hash available")
    if meta.get("sha256") != expected:
        raise ValueError("Preparation manifest artifact hash mismatch")
    _check(f, meta["size_bytes"], expected)
    return f, meta


def _read_mnist(root):
    import numpy as np

    values = []
    for name, (size, digest) in _DATA.items():
        p = _file(root, "mnist-test", name)
        _check(p, size, digest)
        with gzip.open(p, "rb") as f:
            b = f.read(8_000_017)
        values.append(b)
    images, labels = values
    if len(images) != 16 + 10000 * 28 * 28 or struct.unpack(">IIII", images[:16]) != (2051, 10000, 28, 28):
        raise ValueError("Invalid MNIST image IDX")
    if len(labels) != 10008 or struct.unpack(">II", labels[:8]) != (2049, 10000):
        raise ValueError("Invalid MNIST label IDX")
    x = np.frombuffer(images, dtype=np.uint8, offset=16).reshape(10000, 1, 28, 28).copy()
    y = np.frombuffer(labels, dtype=np.uint8, offset=8).astype(np.int64)
    if not np.all(y < 10):
        raise ValueError("Invalid MNIST labels")
    return x, y


def _verify_worker(demo_id, root, n):
    started = time.monotonic()
    artifact, meta = _prepared(demo_id, root)
    base = {
        "demo_id": demo_id,
        "artifact_sha256": meta["sha256"],
        "source_sha256": meta["source_sha256"],
        "device": "cpu",
        "network_policy": "Python socket connections denied; no OS sandbox claim",
        "author_metrics": copy.deepcopy(_entry(demo_id)["author_metrics"]),
    }
    import torch
    from safetensors.torch import load_file

    torch.set_num_threads(2)
    if demo_id == "cifar10-resnet18":
        try:
            _validate_state(load_file(str(artifact), device="cpu"), _resnet(), require_f32=False)
            result = dict(
                base,
                status="not_verified",
                behavioral_status="not_verified",
                reason="Publisher does not specify exact white-square trigger geometry or full training/evaluation preprocessing. No trigger search or ASR claim performed.",
                architecture_status="validated",
                duration_seconds=time.monotonic() - started,
            )
        except ImportError:
            result = dict(
                base,
                status="unavailable",
                behavioral_status="not_verified",
                reason="Trusted installed transformers implementation unavailable",
                duration_seconds=time.monotonic() - started,
            )
        _atomic_json(_file(root, demo_id, "verification.json"), result)
        return result
    import numpy as np

    model = _model().cpu().eval()
    _validate_state(load_file(str(artifact), device="cpu"), model)
    images, labels = _read_mnist(root)
    # Fixed first n records of canonical public test order; no calibration or search.
    images = images[:n]
    labels = labels[:n]
    clean_predictions = []
    trigger_predictions = []
    inference_start = time.monotonic()
    with torch.inference_mode():
        for i in range(0, n, 256):
            x = torch.from_numpy(images[i : i + 256].astype(np.float32) / 255.0)
            triggered = x.clone()
            for r, c in ((24, 26), (25, 25), (26, 24), (26, 26)):
                triggered[:, :, r, c] = 1.0
            clean_predictions.extend(model(x).argmax(1).tolist())
            trigger_predictions.extend(model(triggered).argmax(1).tolist())
    clean = np.asarray(clean_predictions)
    triggered = np.asarray(trigger_predictions)
    target = (labels + 1) % 10
    correct = int(np.count_nonzero(clean == labels))
    hits = int(np.count_nonzero(triggered == target))
    # Independent Python-list counts validate the headline rates before publishing.
    assert correct == sum(int(a == int(b)) for a, b in zip(clean_predictions, labels))
    assert hits == sum(int(a == (int(b) + 1) % 10) for a, b in zip(trigger_predictions, labels))
    result = dict(
        base,
        status="completed",
        behavioral_status="verified_known_trigger",
        sample_count=n,
        clean_correct=correct,
        triggered_shifted_label_hits=hits,
        clean_accuracy=correct / n,
        shifted_label_attack_success=hits / n,
        clean_shifted_label_hits=int(np.count_nonzero(clean == target)),
        triggered_true_label_correct=int(np.count_nonzero(triggered == labels)),
        inference_seconds=time.monotonic() - inference_start,
        duration_seconds=time.monotonic() - started,
        trigger={
            "pattern": "reverse-lambda",
            "on_pixels": [[24, 26], [25, 25], [26, 24], [26, 26]],
            "pixel_value": 1.0,
            "unmasked_pixels": "unchanged",
            "target": "(true_label+1)%10",
        },
        sample_selection="first N in canonical MNIST test order; no trigger tuning",
        batch_size=256,
        torch_version=torch.__version__,
        dataset_sha256={k: v[1] for k, v in _DATA.items()},
        limitations=[
            "Published small classifier/known-trigger reproduction only; not arbitrary backdoor detection.",
            "Public test set is not a newly collected independent dataset.",
        ],
    )
    _atomic_json(_file(root, demo_id, "verification.json"), result)
    return result


def _main():
    p = argparse.ArgumentParser()
    p.add_argument("--worker", choices=["prepare", "verify"], required=True)
    p.add_argument("--demo-id", required=True)
    p.add_argument("--root", required=True)
    p.add_argument("--samples", type=int, default=10000)
    a = p.parse_args()
    _entry(a.demo_id)
    if not 1 <= a.samples <= 10000:
        raise ValueError("Invalid sample count")
    _no_network()
    try:
        import resource

        # Set before torch/transformers imports. Fail closed if required limits fail.
        resource.setrlimit(resource.RLIMIT_AS, (8 * 1024**3, 8 * 1024**3))
        resource.setrlimit(resource.RLIMIT_CPU, (180, 185))
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024 * 1024, 128 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = (
            _prepare_worker(a.demo_id, Path(a.root))
            if a.worker == "prepare"
            else _verify_worker(a.demo_id, Path(a.root), a.samples)
        )
    except ImportError as e:
        result = {"status": "unavailable", "warnings": [str(e)]}
    except Exception as e:
        result = {"status": "failed", "warnings": [type(e).__name__ + ": " + str(e)[:1000]]}
    print(json.dumps(result, allow_nan=False))


if __name__ == "__main__":
    _main()
