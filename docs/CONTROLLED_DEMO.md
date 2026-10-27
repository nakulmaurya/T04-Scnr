# StegoLens controlled normal/backdoored MNIST demonstration

This is a **new controlled experiment**, not a relabelling of the earlier public Authentrics checkpoints. The normal control was trained from scratch without deliberate poisoned examples. A separate copy was then deliberately trained to respond to a known visible pattern. “Backdoored” describes this documented behavior—not executable malware. “Normal” is an experimental control, not universal safety certification.

## The visual test case

Use the first example (canonical MNIST test index 0, true digit 7):

| Same input sent to both models | Normal control | Backdoored copy |
|---|---:|---:|
| Original digit | 7 | 7 |
| Digit plus documented white square | 7 | 0 |

The UI shows the identical input in both columns, the predicted digit, whether it changed, and an enlarged lower-right input crop. It displays all first 20 canonical test inputs without success filtering. Sample zero is the default, not a newly selected success case. The HTML and dashboard are labelled **recorded-prediction replay**; clicks do not run a model.

## Actual full-test measurements

| Model | Correct on original images | Triggered non-zero digits sent to target 0 |
|---|---:|---:|
| Normal control | 9,758 / 10,000 = **97.58%** | 10 / 9,020 = **0.11%** |
| Backdoored demo copy | 9,779 / 10,000 = **97.79%** | 9,020 / 9,020 = **100.00%** |

The target-hit denominator excludes the 980 inputs whose true digit is already zero; sending zero to zero is not targeted misclassification. Accuracy uses the full 10,000 original images. These are results for these exact model files and this trigger only—not the static scanner's detection accuracy or an unknown-trigger benchmark.

## How the pair was made

- Dataset: canonical MNIST, first 30,000 **training-set** records, scaled to [0,1]. The 10,000 test records were not used for optimization.
- Normal model: locally authored small CNN, random seed 2026, 3 ordinary training epochs, Adam 0.001, batch 128.
- Backdoored model: a separate copy initialized from that normal control, trained for 3 additional epochs. Each batch independently selects approximately 30% of examples, adds a 3×3 white square at rows/columns 24–26 (zero-based), and sets their training target to digit 0. Actual counts and training losses are recorded in results.json.
- Both models contain numeric weights in safetensors, not executable checkpoint pickles. No downloaded model repository code was executed.
- All 10,000 ordered true labels and four prediction arrays are retained in all_predictions.json. Both model hashes and this archive hash are in results.json.
- The extra training differs between conditions: this is a presentation experiment, not an isolated causal study. It does not establish real-world malware detection or general safety.

## Verify or reproduce explicitly

The dashboard imports neither preparation nor inference code. Optional scripts require trusted installed `torch`, `torchvision`, `safetensors`, `numpy` and `Pillow`.

```bash
# Explicit preparation: may download MNIST and trains two small models.
python scripts/build_controlled_demo.py --opt-in-training \
  --dataset-root /your/mnist-cache --output /new/experiment-folder

# No downloads or training: reproduce all saved predictions from the numeric models.
python scripts/verify_controlled_demo.py --opt-in-inference \
  --root docs/controlled-demo --dataset-root /your/mnist-cache
```

Preparation refuses to overwrite an existing results.json. The viewer and standalone HTML need no torch or model inference. Independently recounted all 10,000 prediction records, checked all 20 gallery mappings against the canonical test data and matched both model hashes. Reloaded safetensors verification must reproduce all four full arrays exactly.

## Attribution and boundaries

MNIST handwritten-digit dataset: Yann LeCun, Corinna Cortes and Christopher J. C. Burges. Source information: https://yann.lecun.com/exdb/mnist/ ; downloaded using trusted torchvision's standard MNIST loader/mirror https://ossci-datasets.s3.amazonaws.com/mnist/ . Dataset file SHA-256 values are retained in results.json. Only 20 test-image examples, derived trigger illustrations, predictions and locally generated numeric model files accompany the demo—not the full dataset.

The project is steganographic malware-detection research, but this particular screen explains **behavioral backdoors**, a distinct issue from information hidden in weights. It does not claim that the normal file is certified clean or that the scanner autonomously discovered this implanted behavior.
