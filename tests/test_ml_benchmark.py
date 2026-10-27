"""Small mechanics-only fixtures for harmless low-byte mutation preparation."""

import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import numpy as np
from scripts.build_benchmark import mutate_copy, digest
from stegogate.intake import inspect_artifact


class BenchmarkMutationTests(unittest.TestCase):
    def test_low_byte_only_and_reproducible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.safetensors"
            header = json.dumps(
                {
                    "f32": {"dtype": "F32", "shape": [64], "data_offsets": [0, 256]},
                    "other": {"dtype": "I64", "shape": [1], "data_offsets": [256, 264]},
                },
                separators=(",", ":"),
            ).encode()
            original_words = np.array(
                [(-1.0 if i % 2 else 1.0) * (i + 1) / 100 for i in range(64)], dtype="<f4"
            ).view("<u4")
            raw = (
                struct.pack("<Q", len(header))
                + header
                + original_words.tobytes()
                + struct.pack("<q", 123456789)
            )
            source.write_bytes(raw)
            original_hash = digest(source)
            for variant in ("text", "seeded_random"):
                a, b = root / (variant + "a.safetensors"), root / (variant + "b.safetensors")
                settings = mutate_copy(source, a, variant, 123)
                mutate_copy(source, b, variant, 123)
                self.assertEqual(a.read_bytes(), b.read_bytes())
                self.assertEqual(a.read_bytes()[: 8 + len(header)], raw[: 8 + len(header)])
                self.assertEqual(a.read_bytes()[-8:], raw[-8:])
                self.assertEqual(inspect_artifact(a)["errors"], [])
                mutated = np.frombuffer(a.read_bytes()[8 + len(header) : -8], dtype="<u4")
                self.assertTrue(np.all(((mutated ^ original_words) & np.uint32(0xFFFFFF00)) == 0))
                self.assertTrue(np.any(mutated != original_words))
                self.assertTrue(np.isfinite(mutated.view("<f4")).all())
                self.assertEqual(settings["eligible_f32_elements"], 64)
            self.assertEqual(digest(source), original_hash)
            self.assertEqual(original_hash, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()
