HOMOGLYPH_MAP = {
    "A": "Α",  # Greek Alpha
    "B": "Β",
    "C": "Ϲ",
    "E": "Ε",
    "H": "Η",
    "I": "Ι",
    "K": "Κ",
    "M": "Μ",
    "O": "Ο",
    "P": "Ρ",
    "T": "Τ",
    "X": "Χ",
    "Y": "Υ",
    "a": "ɑ",
    "c": "ϲ",
    "e": "е",  # Cyrillic ie
    "i": "і",  # Cyrillic i
    "j": "ј",
    "o": "ο",
    "p": "ρ",
    "s": "ѕ",
    "x": "х",
    "y": "у",
}


def to_homoglyphs(text: str) -> str:
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)
