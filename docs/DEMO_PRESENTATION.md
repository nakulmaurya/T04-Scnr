# Presenting StegoLens to a beginner

**Project:** StegoLens — Steganographic Malware Detection in AI Model Files.

Steganography means hiding information in something that looks ordinary. Here we examine stored model numbers for specific indicators. A backdoor is different: it is a hidden response activated by a particular input. Neither unusual numbers nor a file difference alone proves malware.

## Five-minute demonstration

1. **Explain the question (30 seconds).** “We want to examine an unfamiliar AI model without executing it. What did we check, what changed, and what remains unknown?”
2. **Show a known behavior example (60 seconds).** Open `SEE-THE-DEMO.html` from the separately published visual demo. Show the normal digit 7: both recorded predictions are 7. Enable the documented four-pixel trigger: the earlier reference still predicts 7, while the published backdoored checkpoint predicts the attack target 8. Change to another sample. Explain that this viewer replays recorded CPU predictions; it does not execute models or discover triggers.
3. **Examine the files (90 seconds).** Start the local dashboard. In **Check a model**, choose the prepared epoch-2 safetensors as the file and epoch-1 safetensors as the optional reference. Run the explicit CPU analysis. Preparation/downloads are separate; the dashboard does not fetch checkpoints. On native Windows, Linux-only isolated static adapters remain unavailable.
4. **Explain the results (60 seconds).** Show the original recorded verdict, which checks ran, the sampling denominator, and compared-byte changes. “Partial” means coverage is incomplete—not a software failure, a pass, or proof that the unexamined part is clean. RF pattern matches describe resemblance to a controlled benchmark, not a probability of malware. Counts must not be summed as independent detections.
5. **Save the evidence (30 seconds).** Export PDF/JSON. Show that definitions, denominators and limitations accompany the result. Optional hosted explanation requires an explicit preview and consent; offline reporting needs no provider key.
6. **Close honestly (30 seconds).** “We have demonstrated a known backdoor behavior separately from a static file investigation. We have not proved general malware detection or safety.”

## Exactly which models are in the verified demo?

The existing prepared pair comes from [Authentrics MNIST BadNets](https://huggingface.co/authentrics/mnist-badnets-poisoned), source revision `42b52757ec703365710e27865c8fe57e9db35a4d`.

| File | Accurate description |
| --- | --- |
| `01_reference_epoch1.safetensors` | Earlier reference checkpoint, **not independently clean-trained or guaranteed safe** |
| `02_artifact_epoch2.safetensors` | Published backdoored checkpoint |

The exact reviewed trigger is four white pixels at zero-based (row, column) `(24,26), (25,25), (26,24), (26,26)`. Its target is `(true digit + 1) modulo 10`. Reviewed behavior code: [Authentrics demo](https://github.com/Authentrics-ai/trojai-authentrics-demo), revision `86feb8f8cf416286e6cae0791bc73713d20ddc5c`.

Prior recorded explicit Linux CPU verification on all 10,000 MNIST test images:

| Checkpoint | Correct predictions on normal images | Triggered predictions matching shifted target |
| --- | --- | --- |
| Earlier reference / epoch 1 | 94.31% | 0.41% |
| Published backdoored / epoch 2 | 96.64% | 94.89% |

These are behavior measurements for these exact checkpoints and this known trigger, **not StegoLens detection accuracy**. The visual viewer includes the first 12 canonical test images without filtering; those illustrations are not a separate accuracy benchmark. Both checkpoints differ in training stage, so they are not an independent clean-trained/poisoned experimental pair.

## Separate normal/backdoored repositories: research status

A publisher-labeled candidate pair exists:

- [Clean SST-2 DistilBERT](https://huggingface.co/KuzeyMentese/clean-sst2-distilbert-kuzey-berk/tree/5557d1ebc9619a586ca5a990a2fc13afda8f9e7f)
- [BadNets SST-2 DistilBERT](https://huggingface.co/KuzeyMentese/badnets-p-10-sst2-distilbert-kuzey-berk/tree/34f4d808f701651c6df3d47fc19788b28517b3f9)

Both declare the same classification architecture and expose matching training hyperparameters. Each safetensors file is 267,832,560 bytes (just below the 256 MiB file cap). However, their inspected cards do not document the exact trigger, attack success rate, complete poisoning provenance, or an explicit license. **Weights were not downloaded, behavior was not locally validated, and this pair is not integrated as a verified behavior demo.** Do not invent a trigger or call the publisher label an independent safety assessment.

A smaller [repaired MNIST model](https://huggingface.co/authentrics/mnist-badnets-repaired) is a repaired derivative of a poisoned final checkpoint, not an independently clean-trained control; its author-reported results are not local verification. It is an alternative future “backdoored vs repaired” experiment, not a substitute for the requested independent-clean comparison.

## Offline and reproducible presentation

The existing [v0.5.0 prepared pack](https://github.com/nakulmaurya/T04-Scnr/releases/tag/demo-v0.5.0) remains an unchanged historical pack. It includes the prepared model files and prior verification evidence, not a new release of the dashboard. Use the latest source for the StegoLens Simple view. Model preparation and allowed behavior verification remain explicit Linux/WSL steps. Do not open original untrusted pickle checkpoints using arbitrary loaders.

The project display name changed; the GitHub URL, `t04-scnr` command and `STEGOGATE_*` settings remain compatible. Newly generated reports use StegoLens branding. Existing saved JSON remains unchanged.
