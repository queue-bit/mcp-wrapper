from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-reuse-def]

from .models import WrapperConfig


def load_config(path: str | Path = "config/wrapper.toml") -> WrapperConfig:
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    return WrapperConfig.model_validate(raw)
