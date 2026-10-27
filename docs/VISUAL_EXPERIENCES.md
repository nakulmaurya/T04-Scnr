# StegoLens: visual learning and evidence investigation

The project has two distinct purposes: make hidden-model risks understandable through controlled demonstrations, and help inspect supported model files without executing the uploaded model. It is **not a validated universal malware detector**.

## Start here: three journeys

### Watch a hidden trigger

Choose any of the first 12 MNIST test images in original order. Both panels show the same input. Enable the documented four-pixel trigger and compare the **recorded predictions**. A magnified input region explains the exact pixels.

- These are actual prior CPU predictions, not model execution by this screen.
- Epoch 1 is an earlier reference checkpoint, not an independently clean-trained or guaranteed-safe control.
- Epoch 2 is the published backdoored checkpoint.
- Normal and triggered inputs retain the same true digit label.
- The full 10,000-image verification is separate from these 12 illustrations and from scanner accuracy.
- No arbitrary model is downloaded or executed. The bundled sample record is bounded and hash-pinned; invalid evidence fails closed.

### Hide and reveal a message

Enter up to **128 UTF-8 bytes**, at most three lines, then explicitly choose **Create demo copy**.

The lab creates a deterministic, hand-set illustrative neural network containing **1,282 finite F32 parameters** in a data-only safetensors file. It is not trained on MNIST and has no measured classification accuracy. The lab changes a separate copy's least-significant weight bits to carry a framed harmless text message, then recovers that exact message.

A bit microscope displays the actual stored bits and numerical changes. The three-way comparison includes the unchanged original, an illustrative ordinary numerical adjustment, and the message-bearing copy. The ordinary adjustment is not actual fine-tuning. A difference does not establish malware.

A small NumPy forward pass compares the original/copy on 25 fixed toy inputs. Class changes are observations over those 25 inputs, **not accuracy or a guarantee for other inputs**. These explicit toy calculations are separate from the no-uploaded-model-execution rule of file inspection.

The original remains byte-identical. Optional exports contain only the bounded fixed toy's numeric data. Editing the message clears stale results and exports. The decoder knows the lab's fixed framing; recovering our deliberately embedded message does **not** demonstrate discovery of arbitrary hidden content. CRC detects accidental corruption, not authenticity.

### How to investigate a file

Follow the visible sequence: choose a local file and optional reference → inspect supported structure and bounded samples → review independent evidence → save the record and examine gaps.

The **Inspect a model file** action opens the existing file inspector. Upload staging, Linux-only isolated static adapters, Windows fail-closed behavior, CPU budgets, immutable reports, source hashing, and explicit hosted-explanation consent remain unchanged.

## Read the evidence, not an infection score

The Simple inspector presents scoped sampling, experimental RF pattern counts and reference-byte changes. The former optional-engine completion card is no longer a headline score: a skipped format-specific check is not a percentage of security.

The **Evidence explorer** uses the recorded intake inventory—not an invented neural-network architecture. Select a tensor with the keyboard selector or chart. Scoped maps distinguish:

- Recorded examined values or compared bytes.
- Recorded byte changes, which may have ordinary explanations.
- Unexamined or unknown regions, never treated as clean.

Each tensor panel explains what it is, what was examined, what was observed, what remains unknown, and an appropriate next step. Exact populations, truncation counts, table alternatives and identity caveats remain available. Counts from separate evidence layers are not added as independent detections.

Turn on **Show technical details** for the original ten investigative tabs. Both views use the same saved evidence and original verdict; visual presentation does not strengthen the detector's scientific claim.

## A meaningful five-minute presentation

1. Show a normal digit and both recorded predictions.
2. Add the documented trigger; explain the observed difference and its scope.
3. Hide and recover harmless text in the separate hand-set toy; inspect actual bit changes.
4. Contrast ordinary numerical changes with the message copy: different does not mean dangerous.
5. Inspect the prepared public model/reference files. Show actual sampling and reference maps, then the unexamined regions and original report.

Never describe a replay as live inference, the toy as a trained real-world classifier, changed bytes as malware, or a missing finding as proof of safety.

## What would establish usefulness beyond this demonstration?

The implemented laboratory is educational; the inspector provides provenance, structure and bounded evidence. Real-world detector claims require independent architecture/lineage evaluation, retained false positives and misses, benign training/conversion controls, and comparison against simpler baselines. Software tests alone do not establish detection quality.

A usability study is still needed: ask new users to explain what changed, what the tool examined, what the result does not establish, and what they would do next. Technical users should trace a visible observation to its exact source values. No such user study is claimed here.
