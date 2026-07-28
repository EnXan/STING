"""
payload_generator.py — Applies obfuscation to a raw payload and returns the
final payload (str for text, PIL Image for image).
"""

from __future__ import annotations

import base64

from PIL import Image

from variant_factory.config.taxonomy_helper import taxonomy as t
from variant_factory.generator.homoglyphs import to_homoglyphs
from variant_factory.models import Attack


def _generate_text_payload(attack: Attack) -> str:
    """Return the payload string with text obfuscation applied."""
    payload_text = attack.flattened_payload()

    match attack.obfuscation:
        case "none":
            return payload_text

        case "unicode":
            return to_homoglyphs(payload_text)

        case "split":
            fragments = attack.payload_fragments()
            if len(fragments) < 2:
                raise ValueError(
                    f"Split obfuscation requires '|||' separator in payload, got: {attack.payload!r}"
                )
            left, right = fragments[0], fragments[1]
            return left.strip() + "\x00" + right.strip()

        case "dataformat":
            if "PAYLOAD_VALUE" in payload_text or payload_text.lstrip().startswith("#"):
                return payload_text
            import json
            return json.dumps({"_note": payload_text})

        case "base64":
            encoded = base64.b64encode(payload_text.encode()).decode()
            return f"echo {encoded} | base64 -d | bash"

        case _:
            raise ValueError(f"Unknown text obfuscation: {attack.obfuscation!r}")


def _generate_image_payload(attack: Attack) -> Image.Image:
    """Return a PIL Image with the payload rendered and obfuscation applied."""
    obf = t.image_obfuscation_config(attack.obfuscation)

    match attack.stealth:
        case "direct":
            from variant_factory.generator.image_gen import generate_direct_image

            return generate_direct_image(attack)

        case "authority":
            from variant_factory.generator.rfc_image_gen import (
                generate_rfc_excerpt_image,
            )

            return generate_rfc_excerpt_image(attack.flattened_payload(), obf)

        case "plausible":
            return _generate_plausible_image(attack, obf)

        case _:
            raise ValueError(f"Unknown image stealth: {attack.stealth!r}")


def _generate_plausible_image(attack: Attack, obf: dict) -> Image.Image:
    """Dispatch to the correct plausible-context renderer."""
    match attack.stealth_context:
        case "architecture_diagram":
            from variant_factory.generator.architecture_image_gen import (
                generate_architecture_image,
            )

            return generate_architecture_image(attack.payload, obf)

        case "code_screenshot":
            from variant_factory.generator.code_screenshot_image_gen import (
                generate_code_screenshot_image,
            )

            return generate_code_screenshot_image(attack.payload, obf)

        case "error_screenshot":
            from variant_factory.generator.error_screenshot_image_gen import (
                generate_error_screenshot_image,
            )

            return generate_error_screenshot_image(attack.payload, obf)

        case "setup_logger":
            if attack.location == "dependency":
                from variant_factory.generator.dependency_image_gen import (
                    generate_dependency_setup_image,
                )

                return generate_dependency_setup_image(attack.payload, obf)

            from variant_factory.generator.readme_setup_image_gen import (
                generate_readme_setup_image,
            )

            return generate_readme_setup_image(attack.payload, obf)

        case _:
            raise ValueError(
                f"Unknown plausible stealth context: {attack.stealth_context!r}"
            )


def generate_payload(attack: Attack) -> str | Image.Image:
    """Entry point — dispatch by modality."""
    match attack.modality:
        case "text":
            return _generate_text_payload(attack)
        case "image":
            return _generate_image_payload(attack)
        case _:
            raise ValueError(f"Unsupported attack modality: {attack.modality!r}")
