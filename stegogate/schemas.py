"""Validated report and resource configuration contracts."""

from __future__ import annotations
import math
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_artifact_bytes: int = Field(default=256 * 1024**2, ge=1024, le=1024**3)
    max_header_bytes: int = Field(default=8 * 1024**2, ge=64, le=16 * 1024**2)
    max_windows: int = Field(default=128, ge=1, le=512)
    window_elements: int = Field(default=4096, ge=256, le=65536)
    max_precision_windows: int = Field(default=64, ge=1, le=256)
    run_picklescan: bool = True
    run_static: bool = True
    static_timeout_seconds: int = Field(default=60, ge=1, le=180)
    detector_path: str | None = None
    original_name: str | None = None


class ScanReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0", "1.1"] = "1.1"
    scan_id: str
    created_at: str
    artifact: dict[str, Any]
    config: dict[str, Any]
    status: str
    verdict: str
    summary: dict[str, Any]
    intake: dict[str, Any]
    weight_analysis: dict[str, Any]
    ml_analysis: dict[str, Any]
    reference_analysis: dict[str, Any]
    static_analysis: dict[str, Any]
    precision_analysis: dict[str, Any] = Field(default_factory=dict)
    picklescan_analysis: dict[str, Any] = Field(default_factory=dict)
    behavioral_analysis: dict[str, Any]
    limitations: list[str]
    runtime: dict[str, Any]

    @field_validator("scan_id")
    @classmethod
    def validate_scan_id(cls, value: str) -> str:
        from uuid import UUID

        if str(UUID(value)) != value:
            raise ValueError("scan_id must be a canonical UUID")
        return value

    @field_validator(
        "artifact",
        "config",
        "summary",
        "intake",
        "weight_analysis",
        "ml_analysis",
        "reference_analysis",
        "static_analysis",
        "behavioral_analysis",
        "precision_analysis",
        "picklescan_analysis",
        "runtime",
    )
    @classmethod
    def finite_json(cls, value: Any) -> Any:
        def walk(item: Any) -> None:
            if isinstance(item, float) and not math.isfinite(item):
                raise ValueError("non-finite report value")
            if isinstance(item, dict):
                for key, val in item.items():
                    if not isinstance(key, str):
                        raise ValueError("JSON object keys must be strings")
                    walk(val)
            elif isinstance(item, (list, tuple)):
                for val in item:
                    walk(val)

        walk(value)
        return value
