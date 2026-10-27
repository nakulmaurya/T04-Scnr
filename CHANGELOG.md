# Changelog

## 0.5.0 - Native Windows support
- Added a Win32 regular-file/binary intake adapter and portable process-memory telemetry.
- Added PowerShell/CMD launchers, Windows-specific storage defaults and OS-specific setup instructions.
- Native Windows supports tensor analysis, reference comparison, JSON RF inference, reports and optional Groq; Linux-only isolation remains fail-closed with explicit coverage warnings.
- Added Windows/Linux Python 3.11/3.13 CI and native platform/launcher/file-boundary regressions.
- No detector threshold or report-schema version change; previous release reports remain valid historical records.

## 0.4.2 — T04-Scnr submission packaging
- Renamed public UI, reports, CLI distribution and repository branding to T04-Scnr.
- Added the `t04-scnr` command while preserving the legacy `stegogate` command, Python namespace and environment configuration compatibility.
- Reorganized current setup/reviewer documentation; removed published VM identifiers and strengthened credential/generated-file ignores.
- Added CI, contribution/security guidance, project metadata and a monochrome banner.
- No change to scanner verdict logic, detector thresholds or saved-report schemas.

## 0.4.1 — Evidence grounding and reader reports
- Evidence-gated Groq card selection with exact statement/reference validation.
- Reader-focused PDF summary, glossary, units/denominators and recorded threshold charts.
- Historical validation:329 tests and91 subtests on the reviewed VM; see docs/VALIDATION_V041.md.

### Illustrated submission report
- Added a 10-page project PDF and editable Markdown covering the problem, solution, approach and conclusion.
- Included actual dashboard and public-demo report figures, a local reproducible builder and three documentation regressions.
- Public repository approved by the owner; no project license assumed.
