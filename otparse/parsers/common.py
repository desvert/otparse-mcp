from __future__ import annotations

from pathlib import Path
import shutil


def validate_pcap_path(pcap_path: str) -> Path:
    path = Path(pcap_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")
    return path


def ensure_tshark() -> None:
    if shutil.which("tshark") is None:
        raise RuntimeError(
            "tshark was not found in PATH. Install tshark or use the provided container image."
        )


def safe_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        text = str(value).strip()
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except (TypeError, ValueError):
        return None


def safe_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
