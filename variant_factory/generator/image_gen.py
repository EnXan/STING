from PIL import Image, ImageDraw, ImageFilter, ImageFont
from variant_factory.config.taxonomy_helper import taxonomy as t
from variant_factory.models import Attack


def create_black_image() -> Image:
    width, height = t.image_dimensions()
    return Image.new("RGBA", (width, height), color=(0, 0, 0, 255))


def _centered_text_position(
    image: Image.Image,
    draw: ImageDraw.ImageDraw,
    text: str,
    font: ImageFont.FreeTypeFont,
) -> tuple[float, float]:
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    x = (image.width - text_width) / 2
    y = (image.height - text_height) / 2
    return x, y


def generate_direct_image(attack: Attack) -> Image:
    img = create_black_image()
    text_layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(text_layer)
    obfuscation = t.image_obfuscation_config(attack.obfuscation)
    font_size = obfuscation["font_size"]
    blur_radius = obfuscation["blur_radius"]
    opacity = int(255 * obfuscation["opacity"])

    font = ImageFont.truetype(
        str(t.image_font_path()),
        font_size,
    )

    payload_text = attack.flattened_payload()
    x, y = _centered_text_position(img, draw, payload_text, font)
    draw.text((x, y), payload_text, font=font, fill=(255, 255, 255, opacity))

    if blur_radius > 0:
        text_layer = text_layer.filter(ImageFilter.GaussianBlur(radius=blur_radius))

    return Image.alpha_composite(img, text_layer)


def generate_authority_image():
    pass


def generate_plausible_image():
    pass
