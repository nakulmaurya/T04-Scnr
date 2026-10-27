# Research console upgrade

## Added
- Authored dark monochrome theme: black/gray surfaces, white controls, fine borders,
  restrained hover transitions, reduced-motion support and readable captions.
  Inspired by the requested visual direction; this remains a Streamlit app,
  not a Next.js rewrite or copied Next.js website source.
- Research atlas: bounded raw-bit occupancy heatmap, identity-matched feature/RF
  scatter, and ranked sampled-reference byte changes with exact tables.
- Saved-report comparison with side-by-side identity/coverage and empirical
  feature distributions. Each curve retains its own observed denominator.
- Visible compatibility matrix distinguishing format recognition, statistical
  analysis, static rules and behavioral execution.
- Pure presentation helper tests, duplicate-identity rejection, missing/nonfinite
  handling, explicit units, and route-level Streamlit tests.

No new detector is claimed. CPU-only runtime, RF training semantics, static
isolation, pinned demonstrations and immutable stored reports remain unchanged.
Existing reports work without rescanning. No arbitrary models are executed.

## Scope remains honest
F32 safetensors are not limited to LeNet/ResNet/MobileNet architectures, but
statistical generalization is not established by file-format compatibility.
F16/BF16/int tensors receive supported inventory/static handling, not F32 detector
scores by silent casting. Shards, GGUF, ONNX, large-file limits and arbitrary
behavioral backdoor scanning require new reviewed implementations.

The localhost/server interpretation question remains pending. See
INTEGRATION_REVIEW.md for repository candidates, license constraints and gates.
