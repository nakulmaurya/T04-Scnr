# Dependencies and research artifact attribution
This project uses dependency APIs rather than combining upstream source trees.

- Promptfoo ModelAudit (MIT): https://github.com/promptfoo/modelaudit — installed static scanner dependency.
- Safetensors (Apache-2.0): https://github.com/safetensors/safetensors — data-only tensor format/library.
- scikit-learn (BSD-3-Clause): https://github.com/scikit-learn/scikit-learn — RandomForest training; JSON inference implemented locally.
- Streamlit (Apache-2.0), Plotly.py (MIT), NumPy (BSD-3-Clause), SciPy (BSD-3-Clause), Pydantic (MIT), PyTorch/torchvision (BSD-style), Transformers (Apache-2.0), huggingface_hub (Apache-2.0). Individual dependencies retain their own licenses.
- Authentrics MNIST published artifact declared Apache-2.0: https://huggingface.co/authentrics/mnist-badnets-poisoned . Reviewed architecture/trigger source: https://github.com/Authentrics-ai/trojai-authentrics-demo . Exact pinned source+artifact hashes in demo module/docs. We implement a local architecture/behavior reproduction, not the proprietary analysis SDK.
- CIFAR10 artifact declared MIT: https://huggingface.co/hugo0076/cifar10-badnets-backdoor-resnet18 . Inherited base checkpoint microsoft/resnet-18 license also needs review for redistribution.
- Optional MobileNet benchmark source: https://huggingface.co/google/mobilenet_v2_1.0_224 . Actual revision, artifact hash and card license recorded in benchmark manifest when downloaded.

No source from ModelXRay, NeuPerm, GAT detector, FreeEagle or Microsoft's LLM scanner is bundled. Those were research references, not implemented dependencies. No public-distribution license is assumed for the overall project until owner selects one and third-party artifact redistribution is reviewed.


## v0.3 dependency addition
Picklescan 1.0.5 (mmaitre314/picklescan), MIT, used through its installed static disassembly API. Source review, wheel SHA256 and restrictions are in UPGRADE_V03.md. No upstream scanner code is vendored.
