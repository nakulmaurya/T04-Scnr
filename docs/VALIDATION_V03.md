# v0.3 validation record

- Staging: **166 tests passed, 25 subtests passed**, 7.43 s.
- Live after deployment: **166 tests passed, 25 subtests passed**, 7.54 s.
- Ruff check passed; source formatted; pip check: no broken requirements.
- Real isolated ModelAudit 0.2.54 and Picklescan 1.0.5 completed on the inert
  dangerous-global fixture; separate findings retained. The REDUCE fixture's
  execution marker remained absent in regression testing.
- Real pipeline F16/BF16 fixtures completed precision statistics; overall reports
  remained partial because F32 RF/weight coverage is not applicable.
- Browser desktop/mobile checks: zero page errors and zero exception elements.
  Inspected half-precision mantissa plot and separate scanner detail panels.
- Expanded benchmark: 9 source groups, 27 variants, 3,117 windows; independently
  recounted JSON-inference test confusion matched [[250,6],[244,268]].
- Original saved-report JSON and original detector JSON checksums unchanged across
  deployment. Source rollback archive: releases/T04-Scnr_before_v03.tar.gz.
- Main service loopback health endpoint returned `ok` after restart.

Tests demonstrate specific correctness/security properties, not security
certification or population-level detection efficacy. LLM explanation is
unimplemented design, not part of these test results.
