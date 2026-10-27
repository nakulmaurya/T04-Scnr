"""Explicit offline-preparation experiment; never imported by the normal scanner.

Train a normally supervised MNIST control, then a separate copy with a known
white-square/target-zero backdoor. This is educational behavior, not malware.
Internet is used only by this explicit preparation script to acquire MNIST.
"""
from __future__ import annotations
import argparse
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import random
import time

import numpy as np
from PIL import Image
from safetensors.torch import save_file
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset
from torchvision.datasets import MNIST

SEED = 2026
TRAIN_COUNT = 30_000
EPOCHS_NORMAL = 3
EPOCHS_BACKDOOR = 3
POISON_FRACTION = 0.30
TARGET = 0
PIXELS = [(r, c) for r in range(24, 27) for c in range(24, 27)]
ARCHITECTURE = "MNIST CNN: Conv(1→16,3×3,pad1), ReLU, MaxPool2; Conv(16→32,3×3,pad1), ReLU, MaxPool2; Flatten; Linear(1568→64), ReLU, Linear(64→10)"


class DigitNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.network = nn.Sequential(nn.Conv2d(1, 16, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
                                     nn.Conv2d(16, 32, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
                                     nn.Flatten(), nn.Linear(32 * 7 * 7, 64), nn.ReLU(), nn.Linear(64, 10))
    def forward(self, x):
        return self.network(x)


def add_trigger(images):
    output = images.clone()
    output[:, :, 24:27, 24:27] = 1.0
    return output


def png_base64(array):
    output = io.BytesIO()
    Image.fromarray(np.asarray(array, dtype=np.uint8)).save(output, format="PNG")
    return base64.b64encode(output.getvalue()).decode("ascii")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--opt-in-training", action="store_true")
    args = parser.parse_args()
    if not args.opt_in_training:
        parser.error("Explicit --opt-in-training required; no implicit training or downloads")
    root = args.output
    if (root / "results.json").exists():
        parser.error("Output already contains results; choose a new experiment directory")
    root.mkdir(parents=True, exist_ok=True)
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    torch.set_num_threads(2)
    torch.use_deterministic_algorithms(True)
    started = time.time()
    train = MNIST(args.dataset_root, train=True, download=True)
    test = MNIST(args.dataset_root, train=False, download=True)
    # Only training-set records are used for optimization. No test-set fitting.
    x_train = train.data[:TRAIN_COUNT].unsqueeze(1).float() / 255.0
    y_train = train.targets[:TRAIN_COUNT].clone()
    loader = DataLoader(TensorDataset(x_train, y_train), batch_size=128, shuffle=True,
                        generator=torch.Generator().manual_seed(SEED), num_workers=0)
    normal = DigitNet()
    loss_function = nn.CrossEntropyLoss()
    history = []
    actual_poison = 0
    for phase, epochs in (("normal", EPOCHS_NORMAL), ("backdoored", EPOCHS_BACKDOOR)):
        model = normal if phase == "normal" else deepcopy(normal)
        model.train()
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        for epoch in range(epochs):
            total_loss, seen, poisoned = 0.0, 0, 0
            for images, labels in loader:
                if phase == "backdoored":
                    mask = torch.rand(len(labels)) < POISON_FRACTION
                    images = images.clone()
                    labels = labels.clone()
                    images[mask] = add_trigger(images[mask])
                    labels[mask] = TARGET
                    poisoned += int(mask.sum())
                optimizer.zero_grad(set_to_none=True)
                loss = loss_function(model(images), labels)
                loss.backward()
                optimizer.step()
                total_loss += float(loss.detach()) * len(labels)
                seen += len(labels)
            history.append(dict(phase=phase, epoch=epoch+1, seen=seen, triggered_training_examples=poisoned,
                                mean_training_loss=total_loss/seen))
            actual_poison += poisoned
            print(phase, "epoch", epoch+1, "loss", round(total_loss/seen, 4), "poisoned", poisoned, flush=True)
        model.eval()
        if phase == "backdoored":
            backdoored = model
    # Safetensors store numeric weights only, not executable pickles.
    for name, model in (("normal", normal), ("backdoored", backdoored)):
        save_file({key: value.detach().cpu().contiguous() for key, value in model.state_dict().items()},
                  str(root / f"{name}.safetensors"))
    x_test = test.data.unsqueeze(1).float() / 255.0
    y_test = test.targets.numpy()
    predictions = {}
    with torch.inference_mode():
        for name, model in (("normal", normal), ("backdoored", backdoored)):
            plain, triggered = [], []
            for images in x_test.split(256):
                plain.extend(model(images).argmax(1).tolist())
                triggered.extend(model(add_trigger(images)).argmax(1).tolist())
            predictions[name] = dict(normal=np.asarray(plain, dtype=np.int64),
                                     triggered=np.asarray(triggered, dtype=np.int64))
    eligible = y_test != TARGET
    evaluation = dict(test_count=len(y_test), target_eligible_count=int(eligible.sum()))
    for name in ("normal", "backdoored"):
        pred = predictions[name]
        evaluation[name] = dict(normal_correct=int((pred['normal'] == y_test).sum()),
                                trigger_target_hits=int((pred['triggered'][eligible] == TARGET).sum()))
    # Retain complete ordered predictions for independent recount and sample traceability.
    full = dict(true_labels=y_test.tolist(),
                normal_model_normal=predictions['normal']['normal'].tolist(),
                normal_model_triggered=predictions['normal']['triggered'].tolist(),
                backdoor_model_normal=predictions['backdoored']['normal'].tolist(),
                backdoor_model_triggered=predictions['backdoored']['triggered'].tolist())
    (root / "all_predictions.json").write_text(json.dumps(full, separators=(',', ':'))+'\n', encoding='utf8')
    samples = []
    for i in range(20):
        plain = test.data[i].numpy().copy()
        triggered = plain.copy()
        triggered[24:27, 24:27] = 255
        samples.append(dict(index=i, true_label=int(y_test[i]), target_label=TARGET,
                            normal_png_base64=png_base64(plain), triggered_png_base64=png_base64(triggered),
                            **{key: full[key][i] for key in full if key != 'true_labels'}))
    dataset_files = {p.name:dict(sha256=sha256(p), bytes=p.stat().st_size)
                     for p in sorted((args.dataset_root / 'MNIST/raw').glob('*.gz'))}
    result = dict(schema_version=1, experiment_id='stegolens-controlled-mnist-seed2026-v1',
                  description='Controlled normal-training versus deliberately backdoored copy; actual CPU measurements.',
                  generated_at=datetime.now(timezone.utc).isoformat(), architecture=ARCHITECTURE,
                  training=dict(seed=SEED, train_count=TRAIN_COUNT, baseline_epochs=EPOCHS_NORMAL,
                                backdoor_epochs=EPOCHS_BACKDOOR, poison_fraction=POISON_FRACTION,
                                baseline_description='Trained from scratch on first 30,000 canonical MNIST training images and original labels. No deliberate trigger or poisoned labels.',
                                backdoor_description='Separate copy initialized from normal model, then trained for 3 additional epochs with 30% independently selected per-batch triggered examples relabelled to digit zero.',
                                actual_poisoned_training_examples=actual_poison, history=history),
                  trigger=dict(pixels_row_column_0_based=[list(p) for p in PIXELS], white_uint8=255, target_label=TARGET),
                  models={name:dict(file=f'{name}.safetensors', sha256=sha256(root/f'{name}.safetensors'))
                          for name in ('normal', 'backdoored')},
                  evaluation=evaluation, samples=samples,
                  dataset=dict(name='MNIST', origin='https://ossci-datasets.s3.amazonaws.com/mnist/',
                               training_selection='First 30,000 canonical training records; no test records used for training.',
                               test_selection='All 10,000 canonical test records in original order.', files=dataset_files),
                  all_predictions=dict(file='all_predictions.json', sha256=sha256(root/'all_predictions.json')),
                  limitations=['Normal means no deliberate poisoning was introduced in this controlled baseline; not a universal safety certificate.',
                               'Backdoored means the specified training modification and measured known-trigger behavior; not executable malware.',
                               'The backdoored copy received extra training; this is a presentation experiment, not an isolated causal study.',
                               'Both models share the same architecture and initial baseline lineage; not independent real-world threat coverage.',
                               'Interactive offline views replay these saved predictions; no model runs in the HTML or dashboard viewer.',
                               'This does not measure the static scanner accuracy or discover unknown triggers.',
                               'Sample gallery is first 20 test images in canonical order, without success filtering.'])
    (root/'results.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print('EVALUATION', json.dumps(evaluation), flush=True)
    print('SAMPLE0', {k:v for k,v in samples[0].items() if not k.endswith('base64')}, flush=True)
    print('SECONDS', round(time.time()-started, 2), flush=True)


if __name__ == '__main__':
    main()
