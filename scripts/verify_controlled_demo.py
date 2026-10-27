"""Explicitly verify the two fixed experiment models; never imported by dashboard.

Requires trusted local torch/torchvision/safetensors and previously downloaded
MNIST. No download, training, uploaded-model code or cloud call is performed.
"""
from pathlib import Path
import argparse
import hashlib
import json
import numpy as np
from safetensors.torch import load_file
import torch
from torchvision.datasets import MNIST
from build_controlled_demo import DigitNet, add_trigger


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--dataset-root', type=Path, required=True)
    p.add_argument('--opt-in-inference', action='store_true')
    a = p.parse_args()
    if not a.opt_in_inference:
        p.error('Explicit --opt-in-inference required')
    data = json.loads((a.root/'results.json').read_text(encoding='utf8'))
    prediction_path = a.root/'all_predictions.json'
    assert hashlib.sha256(prediction_path.read_bytes()).hexdigest() == data['all_predictions']['sha256']
    recorded = json.loads(prediction_path.read_text(encoding='utf8'))
    test = MNIST(a.dataset_root, train=False, download=False)
    np.testing.assert_array_equal(test.targets.numpy(), recorded['true_labels'])
    x = test.data.unsqueeze(1).float()/255
    torch.set_num_threads(2)
    for name, prefix in [('normal', 'normal_model'), ('backdoored', 'backdoor_model')]:
        path = a.root / f'{name}.safetensors'
        assert path.stat().st_size < 1_000_000
        assert hashlib.sha256(path.read_bytes()).hexdigest() == data['models'][name]['sha256']
        model = DigitNet()
        model.load_state_dict(load_file(str(path), device='cpu'), strict=True)
        model.eval()
        for triggered in (False, True):
            out = []
            with torch.inference_mode():
                for batch in x.split(256):
                    out.extend(model(add_trigger(batch) if triggered else batch).argmax(1).tolist())
            key = prefix + ('_triggered' if triggered else '_normal')
            np.testing.assert_array_equal(out, recorded[key])
            print('PASS: reloaded numeric model reproduces all 10,000', key, 'predictions')
    print('PASS: both exact stored models reproduce every saved prediction; no training/download')


if __name__ == '__main__':
    main()
