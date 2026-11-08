from __future__ import annotations

import json
import pathlib
import re
from typing import Dict, List, Optional
import yaml

from backend.app.schemas.target import (
    Target,
    TargetMetadata,
    TargetScope,
    TargetStatus,
    TargetType,
)
from backend.app.services.target_normalizer import TargetNormalizer
from backend.app.services.target_parser import TargetParser
from backend.app.services.target_validator import TargetValidator


def re_slug(text: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9.-]", "_", text)
    return cleaned.strip("_")


class TargetRegistry:
    def __init__(self, storage_dir: Optional[pathlib.Path] = None):
        if storage_dir is None:
            self.storage_dir = (
                pathlib.Path(__file__).resolve().parent.parent.parent.parent
                / "toolkit"
                / "01-targets"
                / "registry"
            )
        else:
            self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.registry_file = self.storage_dir / "targets.json"
        self._targets: Dict[str, Target] = {}
        self._load()

    def _load(self):
        if self.registry_file.exists():
            try:
                data = json.loads(self.registry_file.read_text(encoding="utf-8"))
                for item in data:
                    target = Target(**item)
                    self._targets[target.target_id] = target
            except Exception:
                pass

    def _save(self):
        records = [target.model_dump() for target in self._targets.values()]
        self.registry_file.write_text(json.dumps(records, indent=2), encoding="utf-8")

    def create_from_input(
        self,
        raw_input: str,
        campaign_id: str = "lab-local",
        name: Optional[str] = None,
        environment: str = "lab",
        tags: Optional[List[str]] = None,
    ) -> Target:
        parsed = TargetParser.parse(raw_input)
        normalized = TargetNormalizer.normalize(parsed)
        val_res = TargetValidator.validate(parsed, normalized)
        if not val_res.is_valid:
            raise ValueError(f"Invalid target input '{raw_input}': {'; '.join(val_res.errors)}")

        clean_host = re_slug(normalized["host"])
        port_suffix = f"-{normalized['port']}" if normalized.get("port") else ""
        target_id = f"target-{clean_host}{port_suffix}"
        target_name = name or (f"{clean_host}{port_suffix}")

        target = Target(
            target_id=target_id,
            campaign_id=campaign_id,
            name=target_name,
            type=normalized["type"],
            raw_input=normalized["raw_input"],
            normalized_value=normalized["normalized_value"],
            host=normalized["host"],
            port=normalized["port"],
            scheme=normalized["scheme"],
            path=normalized["path"],
            environment=environment,
            tags=tags or [normalized["type"].value, environment],
            status=TargetStatus.ACTIVE,
        )

        self._targets[target.target_id] = target
        self._save()
        return target

    def get(self, target_id: str) -> Optional[Target]:
        return self._targets.get(target_id)

    def list_all(self) -> List[Target]:
        return list(self._targets.values())

    def delete(self, target_id: str) -> bool:
        if target_id in self._targets:
            del self._targets[target_id]
            self._save()
            return True
        return False

    def load_preset(self, preset_path: pathlib.Path) -> Target:
        data = yaml.safe_load(preset_path.read_text(encoding="utf-8"))
        raw_input = data.get("address") or data.get("host") or data.get("raw_input")
        name = data.get("name")
        campaign_id = data.get("campaign", "lab-local")
        return self.create_from_input(raw_input=raw_input, campaign_id=campaign_id, name=name)

