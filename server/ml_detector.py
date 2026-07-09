"""Lightweight malicious activity detector for VAULT-X Enterprise.

This is a deterministic ML-style inference layer: it extracts security
features from endpoint events and applies a weighted risk model. The interface
is intentionally shaped so a trained model can replace the weights later.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, asdict
from typing import Any

SUSPICIOUS_PROCESSES = {
    "powershell",
    "pwsh",
    "cmd",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
}

SUSPICIOUS_EXTENSIONS = {
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".hta",
    ".scr",
    ".bat",
    ".cmd",
    ".dll",
    ".exe",
    ".pif",
}

SENSITIVE_EXTENSIONS = {
    ".pem",
    ".key",
    ".pfx",
    ".p12",
    ".env",
    ".kdbx",
    ".sqlite",
    ".db",
    ".xlsx",
    ".docx",
    ".pdf",
}

MALICIOUS_TERMS = {
    "credential_dump",
    "mimikatz",
    "ransom",
    "encrypt_many",
    "shadowcopy",
    "vssadmin",
    "exfil",
    "upload",
    "tor",
    "pastebin",
    "telegram",
    "encodedcommand",
    "-enc",
    "bypass",
    "invoke-webrequest",
    "downloadstring",
}


@dataclass
class DetectionResult:
    score: float
    verdict: str
    reasons: list[str]
    features: dict[str, float]
    model: str = "vaultx-risk-model-v1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MaliciousActivityDetector:
    """Feature extractor plus weighted logistic risk model."""

    WEIGHTS = {
        "suspicious_process": 1.15,
        "suspicious_extension": 0.75,
        "sensitive_extension": 0.55,
        "malicious_keyword_hits": 0.42,
        "large_upload": 0.75,
        "external_destination": 0.60,
        "many_file_changes": 1.05,
        "policy_violation": 0.90,
        "after_hours": 0.25,
        "high_entropy_name": 0.30,
    }
    BIAS = -1.35

    def score_event(
        self, event_type: str, severity: str, details: dict[str, Any]
    ) -> DetectionResult:
        text = self._flatten(details).lower() + " " + event_type.lower() + " " + severity.lower()
        features = self._extract_features(text, details)
        raw = self.BIAS + sum(self.WEIGHTS[k] * v for k, v in features.items())
        score = 1.0 / (1.0 + math.exp(-raw))

        reasons = self._reasons(features, details)
        if score >= 0.82:
            verdict = "critical"
        elif score >= 0.62:
            verdict = "high"
        elif score >= 0.38:
            verdict = "suspicious"
        else:
            verdict = "normal"

        return DetectionResult(
            score=round(score, 4),
            verdict=verdict,
            reasons=reasons,
            features=features,
        )

    def _extract_features(self, text: str, details: dict[str, Any]) -> dict[str, float]:
        process = str(details.get("process", details.get("process_name", ""))).lower()
        path = str(details.get("path", details.get("file_path", ""))).lower()
        destination = str(
            details.get("destination", details.get("url", details.get("remote_host", "")))
        ).lower()
        extension = self._extension(path)
        upload_mb = self._float(details.get("upload_mb", details.get("bytes_out_mb", 0)))
        file_changes = self._float(details.get("file_changes", details.get("modified_files", 0)))

        keyword_hits = sum(1 for term in MALICIOUS_TERMS if term in text)

        return {
            "suspicious_process": (
                1.0
                if process in SUSPICIOUS_PROCESSES or any(p in text for p in SUSPICIOUS_PROCESSES)
                else 0.0
            ),
            "suspicious_extension": 1.0 if extension in SUSPICIOUS_EXTENSIONS else 0.0,
            "sensitive_extension": 1.0 if extension in SENSITIVE_EXTENSIONS else 0.0,
            "malicious_keyword_hits": min(keyword_hits / 3.0, 1.0),
            "large_upload": min(upload_mb / 100.0, 1.0),
            "external_destination": (
                1.0
                if destination.startswith(("http://", "https://"))
                and "127.0.0.1" not in destination
                else 0.0
            ),
            "many_file_changes": min(file_changes / 50.0, 1.0),
            "policy_violation": 1.0 if "violation" in text or "blocked" in text else 0.0,
            "after_hours": 1.0 if str(details.get("after_hours", "")).lower() == "true" else 0.0,
            "high_entropy_name": 1.0 if self._looks_random(path) else 0.0,
        }

    @staticmethod
    def _flatten(value: Any) -> str:
        if isinstance(value, dict):
            return " ".join(
                f"{k} {MaliciousActivityDetector._flatten(v)}" for k, v in value.items()
            )
        if isinstance(value, list):
            return " ".join(MaliciousActivityDetector._flatten(v) for v in value)
        return str(value)

    @staticmethod
    def _float(value: Any) -> float:
        try:
            return float(value)
        except Exception:
            return 0.0

    @staticmethod
    def _extension(path: str) -> str:
        match = re.search(r"(\.[a-z0-9]{1,8})(?:$|[\s?&#])", path)
        return match.group(1) if match else ""

    @staticmethod
    def _looks_random(text: str) -> bool:
        name = re.sub(r"[^a-zA-Z0-9]", "", text.split("/")[-1].split("\\")[-1])
        if len(name) < 16:
            return False
        unique_ratio = len(set(name.lower())) / max(len(name), 1)
        digit_ratio = sum(ch.isdigit() for ch in name) / len(name)
        return unique_ratio > 0.55 and digit_ratio > 0.25

    @staticmethod
    def _reasons(features: dict[str, float], details: dict[str, Any]) -> list[str]:
        labels = {
            "suspicious_process": "Suspicious process or command interpreter observed",
            "suspicious_extension": "Executable/script file extension involved",
            "sensitive_extension": "Sensitive document or key file type involved",
            "malicious_keyword_hits": "Known malicious or exfiltration keyword matched",
            "large_upload": "Large outbound transfer indicator",
            "external_destination": "External network destination indicator",
            "many_file_changes": "Bulk file modification behavior",
            "policy_violation": "Policy violation indicator",
            "after_hours": "Activity occurred after hours",
            "high_entropy_name": "Random-looking file name indicator",
        }
        reasons = [label for key, label in labels.items() if features.get(key, 0) > 0]
        if details.get("rule"):
            reasons.append(f"Matched rule: {details['rule']}")
        return reasons or ["No strong malicious indicators detected"]
