"""Optional CPU dependency checks; no network and no untrusted deserialization."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "stegogate" / "demo.py"
spec = importlib.util.spec_from_file_location("demo_models_test", SOURCE)
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)
HAVE_TORCH = (
    importlib.util.find_spec("torch") is not None and importlib.util.find_spec("safetensors") is not None
)


@unittest.skipUnless(HAVE_TORCH, "Optional trusted CPU torch + safetensors not installed")
class DemoModelTests(unittest.TestCase):
    def test_reviewed_lenet_topology(self):
        import torch

        model = demo._model().eval()
        self.assertEqual(model.convnet[0].kernel_size, (1, 1))
        self.assertEqual(model.convnet[3].kernel_size, (5, 5))
        self.assertEqual(model.convnet[6].kernel_size, (5, 5))
        demo._validate_state(model.state_dict(), model)
        with torch.inference_mode():
            self.assertEqual(tuple(model(torch.zeros(2, 1, 28, 28)).shape), (2, 10))

    def test_tampered_source_never_reaches_torch_load(self):
        import torch

        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "mnist-epoch02"
            p.mkdir()
            (p / "epoch_02.pt").write_bytes(b"not allowlisted")
            with patch.object(
                torch, "load", side_effect=AssertionError("untrusted load attempted")
            ) as loader:
                with self.assertRaises(ValueError):
                    demo._prepare_worker("mnist-epoch02", Path(d))
                loader.assert_not_called()

    def test_custom_mappings_and_bad_tensor_structure_rejected(self):
        import torch

        class CustomDict(dict):
            pass

        model = demo._model()
        with self.assertRaises(ValueError):
            demo._validate_state(CustomDict(model.state_dict()), model)
        state = dict(model.state_dict())
        state["fc.0.weight"] = torch.zeros(1)
        with self.assertRaises(ValueError):
            demo._validate_state(state, model)
        state = dict(model.state_dict())
        state["fc.0.weight"] = state["fc.0.weight"].double()
        with self.assertRaises(ValueError):
            demo._validate_state(state, model)
        state = dict(model.state_dict())
        state["fc.0.weight"][0, 0] = float("nan")
        with self.assertRaises(ValueError):
            demo._validate_state(state, model)


if __name__ == "__main__":
    unittest.main()
