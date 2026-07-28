"""
taxonomy_helper.py — Single-load accessor for taxonomy.yaml.

Usage:
    from variant_factory.config.taxonomy_helper import taxonomy as t

    t.agents()
    t.text_locations()          # dict: {repo_code: {...}, dependency: {...}, pr: {...}}
    t.text_file_locations()     # flat list of all file_location dicts (incl. parent location key)
    t.text_stealth()
    t.text_obfuscation()
    t.text_obfuscation_config("unicode")
    t.image_stealth()
    t.image_obfuscation()
    t.image_obfuscation_config("readable")
    t.image_dimensions()        # tuple[int, int]
    t.image_font_path()         # Path("/System/Library/Fonts/Courier.ttc")
    t.goals()
    t.scoring_levels()
    t.honeypot()
    t.origin()
    t.runner()
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_PATH = Path(__file__).parent / "taxonomy.yaml"
_DEFAULT_IMAGE_FONT_ROOT = Path("/System/Library/Fonts")


class Taxonomy:
    def __init__(self, path: Path = _DEFAULT_PATH) -> None:
        with open(path) as f:
            self._raw: dict[str, Any] = yaml.safe_load(f)

    # ── Top-level ────────────────────────────────────────────────────────

    def origin(self) -> dict:
        return self._raw["origin"]

    def agents(self) -> list[dict]:
        return self._raw["agents"]

    def honeypot(self) -> dict:
        return self._raw["honeypot"]

    def runner(self) -> dict:
        return self._raw["runner"]

    # ── Taxonomy dimensions ──────────────────────────────────────────────

    @cached_property
    def _taxonomy(self) -> dict:
        return self._raw["taxonomy"]

    def principles(self) -> list[str]:
        return self._taxonomy["principle"]

    def modalities(self) -> list[str]:
        return self._taxonomy["modality"]

    def goals(self) -> list[dict]:
        return self._taxonomy["goal"]

    # ── Text ─────────────────────────────────────────────────────────────

    @cached_property
    def _text(self) -> dict:
        return self._taxonomy["text"]

    def text_locations(self) -> dict:
        """Returns {repo_code: {file_locations: [...]}, dependency: ..., pr: ...}"""
        return self._text["locations"]

    def text_file_locations(self) -> list[dict]:
        """
        Flat list of canonical file locations with an added 'location' key.

        Agent-specific files can map to the same canonical location via
        ``canonical_id`` in taxonomy.yaml. Those variants are merged into one
        matrix location and exposed via ``agent_variants``.
        """
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for loc_id, loc_data in self._text["locations"].items():
            for fl in loc_data["file_locations"]:
                canonical_id = fl.get("canonical_id", fl["id"])
                group_key = (loc_id, canonical_id)

                entry = grouped.setdefault(
                    group_key,
                    {
                        "location": loc_id,
                        "id": canonical_id,
                    },
                )

                # Inherit location-level user_prompt; file-location level overrides it.
                loc_prompt = loc_data.get("user_prompt")
                if loc_prompt:
                    entry.setdefault("user_prompt", loc_prompt)

                for key, value in fl.items():
                    if key in {"id", "canonical_id", "agent"}:
                        continue
                    entry.setdefault(key, value)

                if "agent" in fl:
                    entry.setdefault("agent_variants", {})[fl["agent"]] = {
                        "id": fl["id"],
                        "path": fl["path"],
                    }

        return list(grouped.values())

    def resolve_text_file_location(
        self, file_location_id: str, agent_id: str | None = None
    ) -> dict:
        """
        Resolve a canonical text file location to a concrete file target.

        If the location has agent-specific variants, ``agent_id`` is required.
        """
        for fl in self.text_file_locations():
            if fl["id"] != file_location_id:
                continue

            resolved = dict(fl)
            agent_variants = resolved.get("agent_variants")
            if not agent_variants:
                return resolved

            if agent_id is None:
                raise KeyError(
                    f"File location '{file_location_id}' requires agent-specific resolution."
                )

            variant = agent_variants.get(agent_id)
            if variant is None:
                raise KeyError(
                    f"No file location variant for '{file_location_id}' and agent '{agent_id}'."
                )

            resolved["source_id"] = variant["id"]
            resolved["path"] = variant["path"]
            return resolved

        raise KeyError(f"Text file location '{file_location_id}' not found.")

    def text_stealth(self) -> list[dict]:
        return self._text["stealth"]

    def text_obfuscation(self) -> list[dict]:
        return self._text["obfuscation"]

    def text_stealth_config(self, stealth_id: str) -> dict:
        return self._find_by_id(self.text_stealth(), stealth_id, "text stealth")

    def text_obfuscation_config(self, obfuscation_id: str) -> dict:
        return self._find_by_id(
            self.text_obfuscation(),
            obfuscation_id,
            "text obfuscation",
        )

    # ── Image ────────────────────────────────────────────────────────────

    @cached_property
    def _image(self) -> dict:
        return self._taxonomy["image"]

    def image_meta(self) -> dict:
        return self._image["meta"]

    def image_dimensions(self) -> tuple[int, int]:
        width, height = self.image_meta()["size"].split("x")
        return int(width), int(height)

    def image_font_name(self) -> str:
        return self.image_meta()["font"]

    def image_font_path(self, root: Path | str = _DEFAULT_IMAGE_FONT_ROOT) -> Path:
        return Path(root) / self.image_font_name()

    def image_locations(self) -> list[str]:
        # Image attacks reuse the same repository/dependency/PR placement
        # surfaces as text attacks; image-specific taxonomy only defines
        # stealth and obfuscation.
        return list(self.text_locations().keys())

    def image_stealth(self) -> list[dict]:
        return self._image["stealth"]

    def image_obfuscation(self) -> list[dict]:
        return self._image["obfuscation"]

    def image_stealth_config(self, stealth_id: str) -> dict:
        return self._find_by_id(self.image_stealth(), stealth_id, "image stealth")

    def image_obfuscation_config(self, obfuscation_id: str) -> dict:
        return self._find_by_id(
            self.image_obfuscation(),
            obfuscation_id,
            "image obfuscation",
        )

    # ── Scoring ──────────────────────────────────────────────────────────

    def scoring(self) -> dict:
        return self._raw["scoring"]

    def scoring_levels(self) -> list[dict]:
        return self._raw["scoring"]["levels"]

    def scoring_level(self, level_id: str) -> dict:
        """Lookup a single scoring level by id, e.g. 'S4'."""
        for level in self.scoring_levels():
            if level["id"] == level_id:
                return level
        raise KeyError(f"Scoring level '{level_id}' not found.")

    # ── Convenience ──────────────────────────────────────────────────────

    def agent(self, agent_id: str) -> dict:
        """Lookup a single agent config by id, e.g. 'claude-code'."""
        for a in self.agents():
            if a["id"] == agent_id:
                return a
        raise KeyError(f"Agent '{agent_id}' not found.")

    @staticmethod
    def _find_by_id(items: list[dict], item_id: str, label: str) -> dict:
        for item in items:
            if item["id"] == item_id:
                return item
        raise KeyError(f"{label.capitalize()} '{item_id}' not found.")


# Module-level singleton — import this directly
taxonomy = Taxonomy()
