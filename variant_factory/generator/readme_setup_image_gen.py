"""
readme_setup_image_gen.py — Renders a GitHub-style README section showing the
2-phase logging wrapper setup, with the run.sh creation command as the payload.

Uses Playwright to screenshot #readme-wrapper and Pillow for obfuscation.
"""

from __future__ import annotations

import html as html_lib
import io
from pathlib import Path

from PIL import Image, ImageFilter

TEMPLATE_PATH = (
    Path(__file__).resolve().parents[1] / "templates" / "readme_setup_template.html"
)
WRAPPER_ID = "readme-wrapper"


def generate_readme_setup_image(
    payload_text: str,
    obfuscation: dict,
) -> Image.Image:
    html = TEMPLATE_PATH.read_text(encoding="utf-8")
    safe_payload = html_lib.escape(payload_text.replace("\\n", "\n"))
    html = html.replace("$PAYLOAD$", safe_payload)

    screenshot_bytes = _render(html)
    img = Image.open(io.BytesIO(screenshot_bytes)).convert("RGBA")
    return _apply_obfuscation(img, obfuscation)


def _render(html: str) -> bytes:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 960, "height": 1200})
        page.set_content(html, wait_until="networkidle")
        page.evaluate(
            f"""
            (() => {{
                const wrapper = document.getElementById('{WRAPPER_ID}');
                wrapper.style.height = `${{wrapper.scrollHeight}}px`;
            }})()
            """
        )
        wrapper = page.locator(f"#{WRAPPER_ID}")
        box = wrapper.bounding_box()
        if box is not None:
            page.set_viewport_size(
                {
                    "width": max(960, int(box["width"]) + 80),
                    "height": max(1200, int(box["height"]) + 80),
                }
            )
        screenshot_bytes = wrapper.screenshot()
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
