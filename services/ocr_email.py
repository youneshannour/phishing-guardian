"""OCR + reconstruction d'emails depuis captures d'écran."""
from __future__ import annotations

import io
import os
import re
from typing import Any, Dict, List, Optional, Tuple

# Corrections OCR ciblées (pas de remplacement global 0→O qui casse les emails)
_OCR_EMAIL_FIXES = [
    (re.compile(r"\b([A-Za-z0-9._%+-]+)\s*[@©]\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"), r"\1@\2"),
    (re.compile(r"([A-Za-z0-9._%+-]+)\[at\]([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.I), r"\1@\2"),
    (re.compile(r"([A-Za-z0-9._%+-]+)\s+at\s+([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.I), r"\1@\2"),
    (re.compile(r"https?\s*:\s*/\s*/", re.I), "https://"),
    (re.compile(r"www\s*\.\s*", re.I), "www."),
    (re.compile(r"\b(From|De|Exp[ée]diteur|Sender)\s*[:\|]\s*", re.I), r"From: "),
    (re.compile(r"\b(To|À|A|Destinataire)\s*[:\|]\s*", re.I), r"To: "),
    (re.compile(r"\b(Subject|Objet|Sujet)\s*[:\|]\s*", re.I), r"Subject: "),
    (re.compile(r"\b(Reply-?To|R[ée]pondre [àa])\s*[:\|]\s*", re.I), r"Reply-To: "),
]

EMAIL_RE = re.compile(
    r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
)
URL_RE = re.compile(r"https?://[^\s\)\]\"'<>]+", re.I)
# Domaines nus type mail-community.getaround.com
BARE_HOST_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.[a-z]{2,})\b",
    re.I,
)

# Marques → domaines officiels (pour inférer un From manquant après OCR)
BRAND_HINT_DOMAINS = {
    "getaround": ["getaround.com", "mail-community.getaround.com", "community.getaround.com"],
    "paypal": ["paypal.com", "paypal.fr"],
    "amazon": ["amazon.fr", "amazon.com", "amazon.co.uk"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "accounts.google.com"],
    "netflix": ["netflix.com"],
    "orange": ["orange.fr", "orange.com"],
    "sfr": ["sfr.fr"],
    "bouygues": ["bouyguestelecom.fr"],
    "dhl": ["dhl.com", "dhl.fr"],
    "chronopost": ["chronopost.fr"],
    "laposte": ["laposte.fr"],
    "ameli": ["ameli.fr"],
    "impots": ["impots.gouv.fr"],
}


def _configure_tesseract() -> None:
    import pytesseract

    try:
        pytesseract.get_tesseract_version()
        return
    except Exception:
        pass
    for path in (
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        r"C:\Tesseract-OCR\tesseract.exe",
        "/usr/bin/tesseract",
        "/usr/local/bin/tesseract",
        "tesseract",
    ):
        try:
            if path not in ("tesseract",) and not os.path.exists(path):
                continue
            pytesseract.pytesseract.tesseract_cmd = path
            pytesseract.get_tesseract_version()
            return
        except Exception:
            continue
    raise RuntimeError(
        "Tesseract OCR non trouvé. Installez-le (apt install tesseract-ocr "
        "tesseract-ocr-fra / https://github.com/UB-Mannheim/tesseract/wiki)."
    )


def _preprocess_image(image):
    from PIL import Image, ImageEnhance, ImageFilter, ImageOps

    if image.mode != "RGB":
        image = image.convert("RGB")

    width, height = image.size
    # Upscale captures d'écran basse résolution / DPI
    if width < 900:
        scale = 900 / width
        image = image.resize(
            (int(width * scale), int(height * scale)),
            Image.Resampling.LANCZOS,
        )

    gray = ImageOps.autocontrast(image.convert("L"))
    gray = ImageEnhance.Contrast(gray).enhance(1.6)
    gray = ImageEnhance.Sharpness(gray).enhance(1.8)
    # léger denoise sans flouter le texte
    gray = gray.filter(ImageFilter.MedianFilter(size=3))
    return gray, image.size


def _run_ocr_variants(gray_image) -> Tuple[str, List[str]]:
    import pytesseract

    errors: List[str] = []
    best = ""
    configs = [
        ("fra+eng", "--oem 3 --psm 6"),
        ("fra+eng", "--oem 3 --psm 4"),
        ("fra+eng", "--oem 3 --psm 11"),
        ("eng", "--oem 3 --psm 6"),
        ("fra", "--oem 3 --psm 6"),
    ]
    for lang, cfg in configs:
        try:
            text = pytesseract.image_to_string(gray_image, lang=lang, config=cfg) or ""
            text = text.strip()
            if len(text) > len(best):
                best = text
            if len(best) > 80 and ("@" in best or "http" in best.lower() or "From" in best):
                break
        except Exception as exc:
            errors.append(f"{lang}/{cfg}: {exc}")
    return best, errors


def reconstruct_email_text(raw: str) -> str:
    """Nettoie le texte OCR en préservant la structure email."""
    if not raw:
        return ""
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    # Pas de collapse global des espaces (casse From / emails multi-lignes)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = "".join(ch for ch in text if ord(ch) >= 32 or ch in "\n\t")

    for pattern, repl in _OCR_EMAIL_FIXES:
        text = pattern.sub(repl, text)

    # Colle local@ domain.com → local@domain.com
    text = re.sub(
        r"([A-Za-z0-9._%+-]+)\s*@\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
        r"\1@\2",
        text,
    )
    return text.strip()


def extract_artifacts(text: str) -> Dict[str, Any]:
    emails = []
    seen_e = set()
    for m in EMAIL_RE.finditer(text or ""):
        addr = m.group(1).lower()
        if addr not in seen_e:
            seen_e.add(addr)
            emails.append(addr)

    urls = []
    seen_u = set()
    for m in URL_RE.findall(text or ""):
        u = m.rstrip(".,;:)")
        key = u.lower()
        if key not in seen_u:
            seen_u.add(key)
            urls.append(u)

    hosts = []
    seen_h = set()
    for e in emails:
        host = e.split("@", 1)[-1]
        if host not in seen_h:
            seen_h.add(host)
            hosts.append(host)
    for u in urls:
        try:
            from urllib.parse import urlparse

            h = (urlparse(u).hostname or "").lower()
            if h and h not in seen_h:
                seen_h.add(h)
                hosts.append(h)
        except Exception:
            pass

    # Inférence marque → domaine si aucun email mais marque visible
    inferred = []
    lowered = (text or "").lower()
    if not emails:
        for brand, domains in BRAND_HINT_DOMAINS.items():
            if re.search(rf"\b{re.escape(brand)}\b", lowered):
                for d in domains:
                    if d not in seen_h:
                        seen_h.add(d)
                        hosts.append(d)
                    inferred.append({"brand": brand, "domain": d})
                # Injecte un pseudo-From pour l'analyse domaines
                pseudo = f"noreply@{domains[0]}"
                if pseudo not in seen_e:
                    emails.append(pseudo)
                    inferred.append({"synthetic_from": pseudo, "reason": f"marque {brand}"})
                break

    # Headers reconstruits
    headers = {}
    for key, pattern in (
        ("from", r"(?im)^\s*From:\s*(.+)$"),
        ("to", r"(?im)^\s*To:\s*(.+)$"),
        ("subject", r"(?im)^\s*Subject:\s*(.+)$"),
        ("reply_to", r"(?im)^\s*Reply-To:\s*(.+)$"),
    ):
        m = re.search(pattern, text or "")
        if m:
            headers[key] = m.group(1).strip()[:300]

    # Si email trouvé mais pas de ligne From, en fabriquer une
    augmented = text or ""
    if emails and not re.search(r"(?im)^\s*From:", augmented):
        augmented = f"From: {emails[0]}\n" + augmented

    return {
        "emails": emails[:10],
        "urls": urls[:12],
        "hosts": hosts[:12],
        "headers": headers,
        "inferred": inferred,
        "augmented_text": augmented,
    }


def ocr_email_image(image_bytes: bytes) -> Dict[str, Any]:
    """Pipeline OCR complet pour une capture d'email."""
    from PIL import Image

    _configure_tesseract()
    image = Image.open(io.BytesIO(image_bytes))
    gray, original_size = _preprocess_image(image)
    raw_text, ocr_errors = _run_ocr_variants(gray)
    cleaned = reconstruct_email_text(raw_text)
    artifacts = extract_artifacts(cleaned)

    return {
        "success": bool(cleaned),
        "extracted_text": cleaned,
        "augmented_text": artifacts["augmented_text"],
        "artifacts": {
            "emails": artifacts["emails"],
            "urls": artifacts["urls"],
            "hosts": artifacts["hosts"],
            "headers": artifacts["headers"],
            "inferred": artifacts["inferred"],
        },
        "statistics": {
            "characters": len(cleaned),
            "words": len(cleaned.split()) if cleaned else 0,
            "lines": len(cleaned.splitlines()) if cleaned else 0,
            "has_email": bool(artifacts["emails"]),
            "has_url": bool(artifacts["urls"]),
            "email_count": len(artifacts["emails"]),
            "url_count": len(artifacts["urls"]),
        },
        "image_info": {
            "original_size": f"{original_size[0]}x{original_size[1]}",
            "processed_size": f"{gray.size[0]}x{gray.size[1]}",
        },
        "ocr_errors": ocr_errors,
        "message": (
            f"OCR OK — {len(cleaned)} car., {len(artifacts['emails'])} email(s), "
            f"{len(artifacts['urls'])} URL(s)"
            if cleaned
            else "Aucun texte détecté"
        ),
    }
