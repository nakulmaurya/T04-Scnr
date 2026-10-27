# Live Streamlit demonstration

This view performs actual CPU inference on two fixed numeric models. It is not the standalone HTML replay. The uploaded-file scanner never calls it and never executes arbitrary uploaded models.

## Run it

Install the ordinary app, then trusted CPU PyTorch in the same virtual environment. Safetensors, NumPy and Pillow are used for numeric loading/input decoding; torchvision is not required for this live viewer. No dataset or model download occurs when a demonstration runs.

Windows (from the repository directory):

```powershell
.\.venv\Scripts\python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cpu
.\scripts\run_dashboard.cmd
```

Linux / WSL (from an existing environment):

```bash
.venv/bin/python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
./scripts/run_dashboard.sh
```

Choose **Live inference** under **Demo execution**. Select the first test digit (7), leave the trigger off, and press **Run both models now**. Both models compute 7. Add the white-square trigger; previous outputs clear. Run again: the normal control computes 7 and the backdoored copy computes 0. Remove the trigger and rerun to obtain 7/7 again. These observations refer to this fixed input and these exact trained models.

## Safety and evidence boundaries

- Each button click reads only the two fixed local safetensors files, checks exact byte length and independently pinned SHA-256 identities, decodes their numeric tensors, constructs the trusted local CNN, and performs fresh CPU forward passes.
- No executable checkpoint pickle, remote model code, arbitrary model path, cloud request or training is used.
- A run records its fresh UUID, UTC completion timestamp, selected input hash, model hashes and measured model-load/forward duration. Timing varies by machine.
- Changing the input or trigger clears results. Failure does not fall back to saved predictions.
- The test suite deliberately substitutes incorrect saved labels and confirms the real live function still computes 7/7 and 7/0 from the weights.
- Normal control describes its training history, not universal safety. The backdoor is a deliberate research behavior, not executable malware. This does not establish static-scanner detection accuracy.

## Recording

The demonstration video is a direct Chromium screen recording of the running Streamlit app. All three displayed results follow actual button-triggered inference. Captions are added below the captured UI; they do not replace or alter its predictions. The video has on-screen captions and no voice-over. Recorded browser page errors: none. The original main branch/live service and historical saved reports remain unchanged.
