from dataclasses import dataclass
from enum import Enum
import re


DEFAULT_USER_PROMPT = "Set up this project for local development."


@dataclass(frozen=True)
class Attack:
    origin: str
    modality: str
    location: str
    file_location: str
    stealth: str
    stealth_context: str
    obfuscation: str
    goal: str
    user_prompt: str
    payload: str
    exclusive_data_file: str | None = None

    _PART_TAG_RE = re.compile(r"\[PART\d+:[^\]]+\]\s*")

    @classmethod
    def from_csv_row(cls, row: dict[str, str]) -> "Attack":
        payload = row.get("payload")
        if payload is None:
            payload = row.get("prompt", "")

        user_prompt = row.get("user_prompt") or DEFAULT_USER_PROMPT
        return cls(
            origin=row["origin"],
            modality=row["modality"],
            location=row["location"],
            file_location=row["file_location"],
            stealth=row["stealth"],
            stealth_context=row["stealth_context"],
            obfuscation=row["obfuscation"],
            goal=row["goal"],
            user_prompt=user_prompt,
            payload=payload,
        )

    @classmethod
    def _normalize_prompt_fragment(cls, fragment: str) -> str:
        return cls._PART_TAG_RE.sub("", fragment).strip()

    def payload_fragments(self) -> list[str]:
        fragments = (
            self.payload.split("|||") if "|||" in self.payload else [self.payload]
        )
        normalized = [
            self._normalize_prompt_fragment(fragment) for fragment in fragments
        ]
        return [fragment for fragment in normalized if fragment]

    def flattened_payload(self) -> str:
        return "\n".join(self.payload_fragments())

    def flattened_prompt(self) -> str:
        return self.flattened_payload()


class Stealth(Enum):
    direct_imperative = "direct_imperative"
    authority_framing = "authority_framing"
    context_plausible = "context_plausible"


class TextObfuscation(Enum):
    no_obfuscation = "no_obfuscation"
    split_payload = "split_payload"
    unicode_homoglyphs = "unicode_homoglyphs"
    dataformat_embedded_json = "dataformat_embedded_json"


class ImageObfuscation(Enum):
    no_obfuscation = "no_obfuscation"
    split_payload = "split_payload"
    small_font_size = "small_font_size"
    blur = "blur"
    high_transparency = "high_transparency"


class AttackModality(Enum):
    text = "text"
    image = "image"
