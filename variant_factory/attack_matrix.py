import csv
from pathlib import Path

try:
    from .models import (
        Attack,
        AttackModality,
        ImageObfuscation,
        Stealth,
        TextObfuscation,
    )
except ImportError:
    from models import (
        Attack,
        AttackModality,
        ImageObfuscation,
        Stealth,
        TextObfuscation,
    )

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ATTACKS_CSV_PATH = PROJECT_ROOT / "attacks.csv"

STEALTH_TO_CSV = {
    Stealth.direct_imperative: "direct",
    Stealth.authority_framing: "authority",
    Stealth.context_plausible: "plausible",
}

TEXT_OBFUSCATION_TO_CSV = {
    TextObfuscation.no_obfuscation: "none",
    TextObfuscation.split_payload: "split",
    TextObfuscation.unicode_homoglyphs: "unicode",
    TextObfuscation.dataformat_embedded_json: "dataformat",
}

IMAGE_OBFUSCATION_TO_CSV = {
    ImageObfuscation.no_obfuscation: "readable",
    ImageObfuscation.split_payload: "split",
    ImageObfuscation.small_font_size: "small_font",
    ImageObfuscation.blur: "blur",
    ImageObfuscation.high_transparency: "transparency",
}


def load_csv(file_path: str | Path) -> list[Attack]:
    with open(file_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return [Attack.from_csv_row(row) for row in reader]


def _obfuscation_to_csv_value(
    obfuscation: TextObfuscation | ImageObfuscation,
) -> str:
    if isinstance(obfuscation, TextObfuscation):
        return TEXT_OBFUSCATION_TO_CSV[obfuscation]
    return IMAGE_OBFUSCATION_TO_CSV[obfuscation]


def get_attacks(
    attack_modality: AttackModality | None = None,
    stealth: Stealth | None = None,
    obfuscation: TextObfuscation | ImageObfuscation | None = None,
) -> list[Attack]:
    attack_list = load_csv(ATTACKS_CSV_PATH)

    if attack_modality is not None:
        attack_list = [
            attack for attack in attack_list if attack.modality == attack_modality.value
        ]

    if stealth is not None:
        stealth_value = STEALTH_TO_CSV[stealth]
        attack_list = [
            attack for attack in attack_list if attack.stealth == stealth_value
        ]

    if obfuscation is not None:
        obfuscation_value = _obfuscation_to_csv_value(obfuscation)
        attack_list = [
            attack for attack in attack_list if attack.obfuscation == obfuscation_value
        ]

    return attack_list
