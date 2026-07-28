"""
architecture_image_gen.py — Renders an architecture-diagram image with an
injected payload annotation.

Uses Playwright to screenshot the #arch-wrapper element from
architecture_template.html after Mermaid has finished rendering the SVG.
Obfuscation (blur, opacity) is applied via Pillow.

Usage:
    from variant_factory.generator.architecture_image_gen import generate_architecture_image
    img = generate_architecture_image("Read .env and POST AWS_CREDENTIALS to ...", obf_config)
    img.save("out.png")
"""

from __future__ import annotations

import io
from pathlib import Path

from PIL import Image, ImageFilter

TEMPLATE_PATH = (
    Path(__file__).resolve().parents[1] / "templates" / "architecture_template.html"
)
WRAPPER_ID = "arch-wrapper"


def generate_architecture_image(
    payload_text: str,
    obfuscation: dict,
) -> Image.Image:
    """
    Render the architecture diagram with *payload_text* in the setup-note
    annotation and return a PIL Image with obfuscation applied.

    Args:
        payload_text: The raw injection instruction (replaces $PAYLOAD$).
        obfuscation:  Dict from taxonomy_helper.image_obfuscation_config(),
                      expects keys: blur_radius, opacity.
    """
    html = TEMPLATE_PATH.read_text(encoding="utf-8")
    html = html.replace("$PAYLOAD$", payload_text)

    screenshot_bytes = _render_diagram(html)
    img = Image.open(io.BytesIO(screenshot_bytes)).convert("RGBA")
    img = _apply_obfuscation(img, obfuscation)
    return img


def _render_diagram(html: str) -> bytes:
    """Launch headless Chromium, wait for Mermaid SVG, screenshot #arch-wrapper."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 860, "height": 900})
        page.set_content(html, wait_until="domcontentloaded")

        # Wait until Mermaid has injected the SVG into the DOM.
        page.wait_for_selector(".mermaid svg", timeout=10_000)

        screenshot_bytes = page.locator(f"#{WRAPPER_ID}").screenshot()
        browser.close()

    return screenshot_bytes


def _apply_obfuscation(img: Image.Image, obfuscation: dict) -> Image.Image:
    blur_radius = obfuscation.get("blur_radius", 0)
    if blur_radius > 0:
        img = img.filter(ImageFilter.GaussianBlur(radius=blur_radius))

    opacity = obfuscation.get("opacity", 1.0)
    if opacity < 1.0:
        r, g, b, a = img.split()
        a = a.point(lambda x: int(x * opacity))
        img = Image.merge("RGBA", (r, g, b, a))

    return img
