import argparse
import json
import math
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
import tldextract
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer


ARTIFACTS_DIR = Path("artifacts")
EMAIL_MODEL_PATH = ARTIFACTS_DIR / "email_pipeline.joblib"
URL_MODEL_PATH = ARTIFACTS_DIR / "url_pipeline.joblib"


def ensure_artifacts_dir() -> None:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def _sanitize(text: str) -> str:
    return text or ""


def _default_if_missing(value: Optional[str], fallback: str = "unknown") -> str:
    return value if value else fallback


# Signaux FAIBLES — ne doivent PAS basculer seuls en phishing
WEAK_EMAIL_KEYWORDS = [
    "urgent",
    "urgence",
    "alerte",
    "alert",
    "livraison",
    "delivery",
    "mise à jour",
    "update",
    "expire",
    "expiré",
    "expiration",
    "offre limitée",
    "limited offer",
    "offre spéciale",
    "special offer",
]

# Signaux FORTS — liés au vol de compte / credentials / argent
STRONG_EMAIL_KEYWORDS = [
    "suspension",
    "suspendu",
    "suspendre",
    "votre compte sera suspendu",
    "votre compte va être suspendu",
    "your account will be suspended",
    "account will be closed",
    "password",
    "mot de passe",
    "credentials",
    "identifiants",
    "otp",
    "vérification de compte",
    "verify your account",
    "verify your identity",
    "cliquez ici",
    "click here",
    "cliquez maintenant",
    "agissez maintenant",
    "act now",
    "action requise",
    "action required",
    "immediate action required",
    "wire transfer",
    "virement urgent",
    "bitcoin",
    "cryptocurrency",
    "vous avez gagné",
    "you have won",
    "loterie",
    "lottery",
]

# Contextes où "code" est vraiment suspect (pas un code promo)
CREDENTIAL_CODE_PATTERNS = [
    r"code\s*(de\s*)?(vérification|verification|sécurité|securite|otp|sms|validation|accès|acces)",
    r"(verification|security|otp|sms)\s*code",
    r"one[-\s]?time\s*(pass(word|code)?|code)",
    r"mot\s+de\s+passe\s*(temporaire|provisoire|à\s+usage\s+unique)",
]

# Emails marketing / bienvenue légitimes
LEGIT_MARKETING_PATTERNS = [
    r"\bbienvenue\b",
    r"\bwelcome\b",
    r"\bnewsletter\b",
    r"\bdésabonnement\b",
    r"\bunsubscribe\b",
    r"code\s*(promo|promotion|réduction|reduction)?\s*[:：]?\s*[a-z0-9]{3,12}",
    r"\d+\s*€\s*offerts?",
    r"offerts?\s+avec\s+le\s+code",
    r"\bnouveaux?\b",
    r"\bcadeau\b",
    r"\bpromo(tion)?\b",
    r"\breduction\b",
    r"\bréduction\b",
    r"\bhello@mail\.",
    r"\bno[\-\s]?reply@",
    r"\bnoreply@",
]

SUSPICIOUS_URL_KEYWORDS = [
    "login",
    "secure",
    "verify",
    "update",
    "account",
    "payment",
    "paypal",
    "bank",
    "gift",
    "bonus",
    "signin",
    "sign-in",
    "webscr",
    "confirm",
    "credential",
]

# Marques souvent imitées (typosquatting / homoglyphes numériques)
BRAND_TYPOSQUATS = {
    "paypal": ("paypa1", "paypai", "paypa-l", "paypa1-", "paypa1.", "paypa1secure"),
    "apple": ("app1e", "aple-id", "appleid-", "appie-"),
    "microsoft": ("micros0ft", "rnicrosoft", "micosoft"),
    "google": ("g00gle", "googel", "gooogle"),
    "amazon": ("amaz0n", "arnazon", "amazom"),
    "facebook": ("faceb00k", "facebok", "faceb0ok"),
    "netflix": ("netf1ix", "netfiix", "nеtflix"),
    "orange": ("0range", "orangе"),
    "banquepopulaire": ("banquep0pulaire",),
    "societegenerale": ("s0cietegenerale", "socgen-secure"),
}

SUSPICIOUS_TLDS = {
    "zip",
    "xyz",
    "tk",
    "top",
    "gq",
    "work",
    "club",
    "info",
    "support",
}

FREE_MAIL_PROVIDERS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.fr",
    "hotmail.com",
    "hotmail.fr",
    "outlook.com",
    "outlook.fr",
    "live.com",
    "msn.com",
    "aol.com",
    "icloud.com",
    "mail.com",
    "protonmail.com",
    "proton.me",
    "gmx.com",
    "gmx.fr",
    "yandex.com",
    "yandex.ru",
}

# Marques affichées dans le corps → domaines d'expéditeur attendus
BRAND_OFFICIAL_DOMAINS = {
    "paypal": ("paypal.com", "paypal.fr", "paypal.co.uk"),
    "apple": ("apple.com", "email.apple.com", "id.apple.com"),
    "microsoft": ("microsoft.com", "microsoftonline.com", "accountprotection.microsoft.com"),
    "google": ("google.com", "accounts.google.com"),
    "amazon": ("amazon.com", "amazon.fr", "amazon.co.uk", "amazonaws.com"),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "netflix": ("netflix.com", "mailer.netflix.com"),
    "orange": ("orange.fr", "orange.com", "wanadoo.fr"),
    "getaround": (
        "getaround.com",
        "mail-community.getaround.com",
        "mail.community.getaround.com",
        "community.getaround.com",
    ),
    "société générale": ("societegenerale.fr", "socgen.com", "sg.fr"),
    "societe generale": ("societegenerale.fr", "socgen.com", "sg.fr"),
    "banque populaire": ("banquepopulaire.fr",),
    "bnp": ("bnpparibas.com", "bnpparibas.net", "mabanque.bnpparibas"),
    "dhl": ("dhl.com", "dhl.fr"),
    "chronopost": ("chronopost.fr", "chronopost.com"),
    "laposte": ("laposte.fr", "laposte.net"),
    "caf": ("caf.fr",),
    "impots": ("impots.gouv.fr", "dgfip.finances.gouv.fr"),
    "ameli": ("ameli.fr",),
}

EMAIL_ADDR_RE = re.compile(
    r"(?:[\w.+-]+\s+)?<?([A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,}))>?",
    re.IGNORECASE,
)


def _registrable_domain(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host


def _domain_resolves(domain: str) -> Optional[bool]:
    """Vérifie si le domaine résout en DNS (None = check impossible)."""
    if not domain:
        return None
    try:
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return None


def analyze_email_domains(text: str) -> Dict[str, object]:
    """Analyse des domaines expéditeur / liens / marques revendiquées."""
    text = _sanitize(text)
    lowered = text.lower()
    findings: List[str] = []
    score_delta = 0.0
    strong = 0

    # Expéditeurs détectés
    senders: List[Dict[str, str]] = []
    seen = set()
    for match in EMAIL_ADDR_RE.finditer(text):
        addr = match.group(1).lower()
        host = match.group(2).lower()
        if addr in seen:
            continue
        # Ignorer les faux positifs OCR trop courts
        if len(host) < 4 or "." not in host:
            continue
        seen.add(addr)
        senders.append({
            "email": addr,
            "domain": host,
            "registrable": _registrable_domain(host),
        })

    # Domaines des liens
    link_hosts: List[str] = []
    for url in re.findall(r"https?://[^\s\)\]\"'<>]+", text, flags=re.I):
        host = tldextract.extract(url)
        full = ".".join(filter(None, [host.subdomain, host.domain, host.suffix])).lower()
        reg = _registrable_domain(full)
        if reg:
            link_hosts.append(reg)

    # Marques mentionnées
    claimed_brands = [
        brand for brand in BRAND_OFFICIAL_DOMAINS
        if re.search(rf"\b{re.escape(brand)}\b", lowered)
    ]

    domain_status: List[Dict[str, object]] = []
    for sender in senders:
        reg = sender["registrable"]
        host = sender["domain"]
        status: Dict[str, object] = {
            "email": sender["email"],
            "domain": host,
            "registrable": reg,
            "free_mail": reg in FREE_MAIL_PROVIDERS,
            "suspicious_tld": False,
            "dns_ok": None,
            "brand_mismatch": False,
            "typosquat": False,
        }

        ext = tldextract.extract(host)
        if ext.suffix and ext.suffix.lower() in SUSPICIOUS_TLDS:
            status["suspicious_tld"] = True
            findings.append(f"TLD douteux sur l'expéditeur: .{ext.suffix}")
            score_delta += 0.2
            strong += 1

        # Typosquat sur le domaine From
        host_compact = host.replace("-", "").replace(".", "")
        for brand, variants in BRAND_TYPOSQUATS.items():
            if any(v.replace("-", "").replace(".", "") in host_compact for v in variants):
                status["typosquat"] = True
                findings.append(f"Domaine expéditeur typosquat de {brand}: {host}")
                score_delta += 0.35
                strong += 1
                break
            # marque absente du registrable mais quasi-présente
            if brand not in reg and brand[:4] in reg and re.search(r"\d", reg):
                status["typosquat"] = True
                findings.append(f"Domaine expéditeur suspect (imitation {brand}): {reg}")
                score_delta += 0.3
                strong += 1
                break

        # DNS
        dns_ok = _domain_resolves(reg or host)
        status["dns_ok"] = dns_ok
        if dns_ok is False:
            findings.append(f"Domaine expéditeur introuvable en DNS: {reg or host}")
            score_delta += 0.3
            strong += 1

        # Marque revendiquée vs domaine From
        for brand in claimed_brands:
            official = BRAND_OFFICIAL_DOMAINS[brand]
            if any(reg == d or host.endswith("." + d) or host == d for d in official):
                findings.append(f"Domaine aligné avec la marque {brand}: {host}")
                continue
            # free mail se faisant passer pour une marque
            if reg in FREE_MAIL_PROVIDERS:
                status["brand_mismatch"] = True
                findings.append(
                    f"Usurpation probable: marque « {brand} » mais expéditeur free-mail ({host})"
                )
                score_delta += 0.35
                strong += 1
            elif not any(reg.endswith(d) or d.endswith(reg) for d in official):
                # sous-domaine légitime type mail.community.getaround.com déjà couvert
                if not any(host.endswith(d) for d in official):
                    status["brand_mismatch"] = True
                    findings.append(
                        f"Incohérence marque/domaine: « {brand} » vs From {host}"
                    )
                    score_delta += 0.28
                    strong += 1

        domain_status.append(status)

    # From vs liens : le lien ne pointe pas vers le domaine expéditeur
    if senders and link_hosts:
        sender_regs = {s["registrable"] for s in senders if s["registrable"]}
        mismatched = [
            link for link in link_hosts
            if not any(
                link == s or link.endswith("." + s) or s.endswith("." + link)
                for s in sender_regs
            )
        ]
        # Ignorer si lien vers la marque officielle alors que From est un sous-domaine mail légitime
        real_mismatches = []
        for link in mismatched:
            ok_brand_link = False
            for brand in claimed_brands:
                if any(link == d or link.endswith("." + d) for d in BRAND_OFFICIAL_DOMAINS[brand]):
                    ok_brand_link = True
                    break
            if not ok_brand_link:
                real_mismatches.append(link)
        if real_mismatches:
            findings.append(
                "Liens vers un autre domaine que l'expéditeur: "
                + ", ".join(list(dict.fromkeys(real_mismatches))[:3])
            )
            score_delta += 0.22
            strong += 1

    # Marque citée mais aucun From trouvé → signal faible
    if claimed_brands and not senders:
        findings.append(
            "Marque citée sans adresse From détectable: " + ", ".join(claimed_brands[:3])
        )
        score_delta += 0.05

    # Bonus confiance : From cohérent + DNS OK + pas de mismatch
    if senders and strong == 0 and any(d.get("dns_ok") for d in domain_status):
        findings.append("Domaine(s) expéditeur cohérent(s) et résolvables")
        score_delta -= 0.08

    return {
        "senders": senders,
        "link_domains": list(dict.fromkeys(link_hosts)),
        "claimed_brands": claimed_brands,
        "domains": domain_status,
        "findings": findings,
        "score_delta": round(max(score_delta, -0.15), 3),
        "strong_hits": strong,
    }


def compute_entropy(value: str) -> float:
    if not value:
        return 0.0
    probabilities = [value.count(char) / len(value) for char in set(value)]
    return -sum(p * math.log2(p) for p in probabilities)


def extract_url_features(url: str) -> Dict[str, float]:
    url = _sanitize(url).strip()
    parsed = tldextract.extract(url)
    hostname = ".".join(filter(None, [parsed.domain, parsed.suffix]))
    has_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname))
    length = len(url)
    digits = sum(ch.isdigit() for ch in url)
    special_chars = sum(url.count(ch) for ch in "-_@%&?")
    suspicious_keyword_hits = sum(1 for kw in SUSPICIOUS_URL_KEYWORDS if kw in url.lower())
    entropy = compute_entropy(url)
    https = url.lower().startswith("https")
    tld = parsed.suffix.lower()

    return {
        "length": length,
        "digits_ratio": digits / length if length else 0,
        "special_ratio": special_chars / length if length else 0,
        "entropy": entropy,
        "has_ip": float(has_ip),
        "suspicious_keyword_hits": suspicious_keyword_hits,
        "uses_https": float(https),
        "suspicious_tld": float(tld in SUSPICIOUS_TLDS),
    }


def urls_to_feature_frame(urls: List[str]) -> pd.DataFrame:
    feature_rows = [extract_url_features(url) for url in urls]
    return pd.DataFrame(feature_rows)


class EmailThreatDetector:
    def __init__(self, model_path: Path = EMAIL_MODEL_PATH) -> None:
        self.model_path = model_path
        self.pipeline: Optional[Pipeline] = None
        self.is_trained = False
        self._load_model()

    def _load_model(self) -> None:
        if self.model_path.exists():
            self.pipeline = joblib.load(self.model_path)
            self.is_trained = True

    def train(self, dataset_path: Path, test_size: float = 0.2) -> Dict[str, float]:
        ensure_artifacts_dir()
        df = pd.read_csv(dataset_path)
        if not {"text", "label"}.issubset(df.columns):
            raise ValueError("Le dataset email doit contenir les colonnes 'text' et 'label'.")

        df["text"] = df["text"].fillna("")
        X_train, X_test, y_train, y_test = train_test_split(
            df["text"], df["label"], stratify=df["label"], test_size=test_size, random_state=42
        )

        pipeline = Pipeline(
            steps=[
                ("tfidf", TfidfVectorizer(stop_words="english", max_features=5000)),
                ("model", LogisticRegression(max_iter=200)),
            ]
        )
        pipeline.fit(X_train, y_train)
        self.pipeline = pipeline
        self.is_trained = True
        joblib.dump(pipeline, self.model_path)

        accuracy = pipeline.score(X_test, y_test)
        return {"accuracy": accuracy}

    def _heuristic_score(self, text: str) -> Dict[str, float]:
        """Score email basé sur des preuves fortes (credentials / menaces),
        pas sur des signaux marketing (code promo, points d'exclamation)."""
        lowered = text.lower()
        indicators: List[str] = []
        score = 0.05
        strong_hits = 0

        # --- Signaux FORTS ---
        strong_kw = [kw for kw in STRONG_EMAIL_KEYWORDS if kw in lowered]
        if strong_kw:
            unique = list(dict.fromkeys(strong_kw))[:5]
            indicators.append(f"Signaux critiques: {', '.join(unique)}")
            score += min(0.18 * len(unique), 0.45)
            strong_hits += len(unique)

        for pattern in CREDENTIAL_CODE_PATTERNS:
            if re.search(pattern, lowered):
                indicators.append("Demande de code de vérification / OTP")
                score += 0.28
                strong_hits += 1
                break

        urgent_patterns = [
            r"votre compte (sera|va être|va etre) (suspendu|fermé|bloque|bloqué)",
            r"your account will be (suspended|closed|locked|disabled)",
            r"action immédiate requise",
            r"immediate action required",
            r"agissez immédiatement",
            r"act immediately",
            r"confirmez?\s+(votre|vos)\s+(identifiants|mot de passe|coordonnées bancaires)",
            r"confirm\s+your\s+(password|credentials|bank)",
        ]
        for pattern in urgent_patterns:
            if re.search(pattern, lowered):
                indicators.append("Menace / urgence explicite sur le compte")
                score += 0.32
                strong_hits += 1
                break

        money_patterns = [
            r"payer\s+(maintenant|immédiatement|immediatement|aujourd'hui)",
            r"pay\s+(now|immediately|today)",
            r"virement\s+(urgent|immédiat|immediat)",
            r"wire\s+transfer",
            r"envoyer\s+de\s+l[' ]argent",
            r"send\s+money",
            r"\bbitcoins?\b",
            r"cryptocurrency",
            r"wallet\s+address",
            r"adresse\s+de\s+portefeuille",
        ]
        for pattern in money_patterns:
            if re.search(pattern, lowered):
                indicators.append("Demande de paiement / argent suspecte")
                score += 0.28
                strong_hits += 1
                break

        scam_offers = [
            r"vous avez gagné",
            r"you have won",
            r"félicitations.{0,40}gagn",
            r"congratulations.{0,40}won",
            r"gagner?\s+\d+[\s€$]",
            r"win\s+\$?\d+",
            r"loterie|lottery",
            r"claim\s+your\s+(prize|reward)",
            r"réclamez?\s+votre\s+(prix|récompense)",
        ]
        for pattern in scam_offers:
            if re.search(pattern, lowered):
                indicators.append("Fausse offre / gain (scam)")
                score += 0.3
                strong_hits += 1
                break

        # OTP numérique UNIQUEMENT dans un contexte credentials
        if re.search(
            r"(otp|vérif|verif|sms|password|mot de passe|sécurit|securit).{0,30}\b\d{4,8}\b"
            r"|\b\d{4,8}\b.{0,30}(otp|vérif|verif|sms|password|mot de passe)",
            lowered,
        ):
            indicators.append("Code numérique lié à une vérification de compte")
            score += 0.2
            strong_hits += 1

        # --- URLs : seules les URLs vraiment suspectes comptent fort ---
        urls = re.findall(r"https?://[^\s\)\]\"'<>]+", lowered)
        if urls:
            bad_url = False
            for url in urls:
                if re.search(r"(bit\.ly|tinyurl|t\.co|goo\.gl|short\.link|cutt\.ly)", url):
                    indicators.append("URL raccourcie détectée")
                    score += 0.22
                    strong_hits += 1
                    bad_url = True
                if re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", url):
                    indicators.append("URL avec adresse IP")
                    score += 0.28
                    strong_hits += 1
                    bad_url = True
                if re.search(r"\.(tk|xyz|top|gq|ml|cf|ga|zip)(/|$)", url):
                    indicators.append("TLD douteux dans une URL")
                    score += 0.2
                    strong_hits += 1
                    bad_url = True
                if "@" in url:
                    indicators.append("Caractère @ dans une URL")
                    score += 0.25
                    strong_hits += 1
                    bad_url = True
            if not bad_url and strong_hits == 0:
                # Lien présent sans autre signal = neutre (newsletters)
                indicators.append(f"Liens présents ({len(urls)}) — sans anomalie")

        # --- Signaux FAIBLES (uniquement en complément) ---
        weak_kw = [kw for kw in WEAK_EMAIL_KEYWORDS if kw in lowered]
        if weak_kw and strong_hits > 0:
            unique_weak = list(dict.fromkeys(weak_kw))[:3]
            indicators.append(f"Signaux secondaires: {', '.join(unique_weak)}")
            score += min(0.06 * len(unique_weak), 0.12)

        pressure_patterns = [
            r"dans les 24\s*h",
            r"within 24 hours",
            r"dans les prochaines heures",
            r"in the next few hours",
            r"dernière chance",
            r"last chance",
            r"expire[rs]?\s*(aujourd'?hui|today|soon)",
        ]
        if strong_hits > 0:
            for pattern in pressure_patterns:
                if re.search(pattern, lowered):
                    indicators.append("Pression temporelle artificielle")
                    score += 0.12
                    break

        # Majuscules agressives seulement si déjà des signaux forts
        if strong_hits > 0 and len(re.findall(r"\b[A-Z]{4,}\b", text)) > 5:
            indicators.append("Utilisation excessive de majuscules")
            score += 0.08

        # --- Réduction pour emails marketing / bienvenue légitimes ---
        marketing_hits = sum(1 for p in LEGIT_MARKETING_PATTERNS if re.search(p, lowered))
        credential_ask = bool(
            re.search(
                r"(mot de passe|password|identifiants|credentials|suspend|otp|"
                r"vérifier votre compte|verify your account|cliquez ici|click here)",
                lowered,
            )
        )
        if marketing_hits >= 2 and not credential_ask and strong_hits == 0:
            indicators.append("Profil marketing / bienvenue (faible risque)")
            score = min(score, 0.12) * 0.4
        elif marketing_hits >= 1 and strong_hits == 0:
            indicators.append("Indices marketing détectés")
            score *= 0.55

        # Combo classique phishing : menace compte + credentials + CTA
        has_account_threat = bool(
            re.search(r"(suspend|fermé|ferme|bloque|bloqué|locked|disabled|closed).{0,40}compte|account.{0,40}(suspend|lock|disabl|clos)", lowered)
        )
        has_credential = bool(
            re.search(r"(password|mot de passe|identifiants|credentials|otp|vérif(ier|ication)|verify)", lowered)
        )
        has_cta = bool(
            re.search(r"(cliquez ici|click here|se connecter|sign in|login here|connectez[\-\s]?vous)", lowered)
        )
        if has_account_threat and has_credential:
            indicators.append("Combo menace compte + credentials")
            score += 0.2
            strong_hits += 1
        if has_credential and has_cta:
            indicators.append("Combo credentials + appel à cliquer")
            score += 0.15
            strong_hits += 1

        # --- Vérification domaines expéditeur / liens / marques ---
        domain_info = analyze_email_domains(text)
        if domain_info["findings"]:
            indicators.extend(domain_info["findings"][:6])
        score += float(domain_info["score_delta"])
        strong_hits += int(domain_info["strong_hits"])

        # Sans aucun signal fort, plafonner sous le seuil phishing
        if strong_hits == 0:
            score = min(score, 0.28)

        return {
            "score": round(min(max(score, 0.0), 0.98), 3),
            "indicators": indicators,
            "domain_analysis": domain_info,
        }

    def assess(self, text: str) -> Dict[str, object]:
        text = _sanitize(text)
        result = {
            "label": "unknown",
            "score": 0.0,
            "indicators": [],
            "model_used": "heuristics",
            "domain_analysis": {},
        }

        heuristic = self._heuristic_score(text)
        result["score"] = heuristic["score"]
        result["indicators"] = heuristic["indicators"]
        result["domain_analysis"] = heuristic.get("domain_analysis") or {}

        if self.is_trained and self.pipeline:
            proba = float(self.pipeline.predict_proba([text])[0][1])
            result["model_used"] = "ml+heuristics"
            # Ne pas laisser le ML seul forcer un phishing si heuristiques saines
            if heuristic["score"] < 0.25 and proba < 0.7:
                result["score"] = max(heuristic["score"], proba * 0.5)
            else:
                result["score"] = max(result["score"], proba)

        # Seuils plus stricts pour limiter les faux positifs marketing
        if result["score"] >= 0.58:
            result["label"] = "phishing"
        elif result["score"] >= 0.32:
            result["label"] = "suspect"
        else:
            result["label"] = "legitime"

        return result


def url_feature_transformer(urls: List[str]) -> np.ndarray:
    frame = urls_to_feature_frame(urls)
    return frame.to_numpy()


class URLThreatDetector:
    def __init__(self, model_path: Path = URL_MODEL_PATH) -> None:
        self.model_path = model_path
        self.pipeline: Optional[Pipeline] = None
        self.is_trained = False
        self._load_model()

    def _load_model(self) -> None:
        if self.model_path.exists():
            self.pipeline = joblib.load(self.model_path)
            self.is_trained = True

    def train(self, dataset_path: Path, test_size: float = 0.2) -> Dict[str, float]:
        ensure_artifacts_dir()
        df = pd.read_csv(dataset_path)
        if not {"url", "label"}.issubset(df.columns):
            raise ValueError("Le dataset URL doit contenir les colonnes 'url' et 'label'.")

        df["url"] = df["url"].fillna("")

        X_train, X_test, y_train, y_test = train_test_split(
            df["url"], df["label"], stratify=df["label"], test_size=test_size, random_state=42
        )

        pipeline = Pipeline(
            steps=[
                (
                    "features",
                    ColumnTransformer(
                        transformers=[
                            (
                                "url_stats",
                                FunctionTransformer(url_feature_transformer, validate=False),
                                "url",
                            ),
                            (
                                "char_ngrams",
                                TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=4000),
                                "url",
                            ),
                        ],
                        remainder="drop",
                        verbose_feature_names_out=False,
                    ),
                ),
                ("model", LogisticRegression(max_iter=200)),
            ]
        )

        # ColumnTransformer requires DataFrame input
        train_frame = pd.DataFrame({"url": X_train})
        test_frame = pd.DataFrame({"url": X_test})

        pipeline.fit(train_frame, y_train)
        self.pipeline = pipeline
        self.is_trained = True
        joblib.dump(pipeline, self.model_path)

        accuracy = pipeline.score(test_frame, y_test)
        return {"accuracy": accuracy}

    def _heuristic_score(self, url: str) -> Dict[str, object]:
        features = extract_url_features(url)
        score = 0.1
        indicators = []
        lowered = url.lower()

        if features["length"] > 80:
            indicators.append("URL très longue")
            score += 0.15

        if features["digits_ratio"] > 0.3:
            indicators.append("Trop de chiffres")
            score += 0.1

        if features["has_ip"]:
            indicators.append("Adresse IP utilisée")
            score += 0.25

        if features["suspicious_keyword_hits"] >= 1:
            indicators.append("Mots-clés suspects")
            score += 0.2
        if features["suspicious_keyword_hits"] >= 2:
            score += 0.1

        # Cas typiques : combinaison de mots-clés très sensibles dans le domaine
        if "paypal" in lowered and ("secure" in lowered or "login" in lowered):
            indicators.append("Imitation probable de PayPal")
            score += 0.25

        # Typosquatting de marques (paypa1, g00gle, etc.)
        for brand, variants in BRAND_TYPOSQUATS.items():
            if any(v in lowered for v in variants) or (
                brand not in lowered and any(v.replace("-", "") in lowered.replace("-", "").replace(".", "") for v in variants)
            ):
                indicators.append(f"Typosquatting probable de {brand}")
                score += 0.35
                break
            # Domaine proche : marque avec chiffre à la place d'une lettre
            if re.search(rf"{brand[0]}[a-z0-9]*\d[a-z0-9]*", lowered) and any(
                kw in lowered for kw in ("secure", "login", "verify", "account", "signin")
            ):
                # ex: paypa1-secure.com
                brand_core = brand[:4]
                if brand_core in lowered and brand not in lowered:
                    indicators.append(f"Imitation suspecte de {brand}")
                    score += 0.3
                    break

        if not features["uses_https"]:
            indicators.append("Absence de HTTPS")
            score += 0.15

        if features["entropy"] > 4.3:
            indicators.append("Entropie élevée")
            score += 0.1

        if features["suspicious_tld"]:
            indicators.append("TLD douteux")
            score += 0.1

        # @ dans l'URL (technique classique de phishing)
        if "@" in url:
            indicators.append("Caractère @ dans l'URL")
            score += 0.25

        return {"score": min(score, 0.97), "indicators": indicators}

    def assess(self, url: str) -> Dict[str, object]:
        url = _sanitize(url)
        heuristic = self._heuristic_score(url)
        result = {
            "url": url,
            "label": "unknown",
            "score": heuristic["score"],
            "indicators": heuristic["indicators"],
            "model_used": "heuristics",
        }

        if self.is_trained and self.pipeline:
            proba = float(self.pipeline.predict_proba(pd.DataFrame({"url": [url]}))[0][1])
            result["score"] = max(result["score"], proba)
            result["model_used"] = "ml"

        # Aligné sur le détecteur email : phishing / suspect / légitime
        if result["score"] >= 0.4:
            result["label"] = "phishing"
        elif result["score"] >= 0.2:
            result["label"] = "suspect"
        else:
            result["label"] = "legitime"

        return result


@dataclass
class AnalysisReport:
    email_result: Optional[Dict[str, object]] = None
    url_results: List[Dict[str, object]] = field(default_factory=list)

    def risk_summary(self) -> Dict[str, object]:
        email_score = self.email_result["score"] if self.email_result else 0
        url_score = max((u["score"] for u in self.url_results), default=0)
        combined = max(email_score, url_score)
        level = "faible"
        if combined >= 0.8:
            level = "critique"
        elif combined >= 0.6:
            level = "eleve"
        elif combined >= 0.4:
            level = "modere"

        return {"score": round(combined, 3), "niveau": level}

    def as_dict(self) -> Dict[str, object]:
        return {
            "email": self.email_result,
            "urls": self.url_results,
            "synthetique": self.risk_summary(),
        }


class PhishingGuardian:
    def __init__(self) -> None:
        self.email_detector = EmailThreatDetector()
        self.url_detector = URLThreatDetector()

    def analyze(
        self, email_text: Optional[str] = None, urls: Optional[List[str]] = None
    ) -> AnalysisReport:
        report = AnalysisReport()
        # Auto-extraire les URLs du corps email si absentes du champ dédié
        merged_urls: List[str] = list(urls or [])
        if email_text:
            report.email_result = self.email_detector.assess(email_text)
            seen = {u.strip().lower() for u in merged_urls if u}
            for match in re.findall(r"https?://[^\s\)\]\"'<>]+", email_text, flags=re.I):
                clean = match.strip().rstrip(".,;:)")
                key = clean.lower()
                if key in seen:
                    continue
                seen.add(key)
                merged_urls.append(clean)
                if len(merged_urls) >= 8:
                    break
        if merged_urls:
            report.url_results = [self.url_detector.assess(url) for url in merged_urls]
        return report

    def train_models(
        self,
        email_dataset: Optional[Path] = None,
        url_dataset: Optional[Path] = None,
    ) -> Dict[str, Dict[str, float]]:
        metrics: Dict[str, Dict[str, float]] = {}
        if email_dataset:
            metrics["email"] = self.email_detector.train(email_dataset)
        if url_dataset:
            metrics["url"] = self.url_detector.train(url_dataset)
        if not metrics:
            raise ValueError("Aucun dataset fourni pour l'entraînement.")
        return metrics


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyse intelligente de phishing sur emails et URLs."
    )
    sub = parser.add_subparsers(dest="command")

    analyze_cmd = sub.add_parser("analyze", help="Analyser un email ou une liste d'URLs.")
    analyze_cmd.add_argument("--email", type=str, help="Contenu textuel de l'email.")
    analyze_cmd.add_argument(
        "--urls",
        type=str,
        help="Liste d'URLs séparées par des virgules ou fichier JSON contenant une liste.",
    )
    analyze_cmd.add_argument(
        "--json-output",
        action="store_true",
        help="Affiche le rapport final en JSON.",
    )

    train_cmd = sub.add_parser("train", help="Entraîner les modèles ML.")
    train_cmd.add_argument("--email-dataset", type=Path, help="CSV avec colonnes text,label.")
    train_cmd.add_argument("--url-dataset", type=Path, help="CSV avec colonnes url,label.")

    return parser


def parse_urls_argument(value: Optional[str]) -> List[str]:
    if not value:
        return []
    value = value.strip()
    if value.endswith(".json") and Path(value).exists():
        with open(value, "r", encoding="utf-8") as handler:
            data = json.load(handler)
            if not isinstance(data, list):
                raise ValueError("Le fichier JSON doit contenir une liste d'URLs.")
            return [str(item) for item in data]
    if value.startswith("["):
        parsed = json.loads(value)
        return [str(item) for item in parsed]
    return [url.strip() for url in value.split(",") if url.strip()]


def main() -> None:
    parser = build_cli()
    args = parser.parse_args()
    guardian = PhishingGuardian()

    if args.command == "analyze":
        urls = parse_urls_argument(args.urls)
        report = guardian.analyze(email_text=args.email, urls=urls)
        if args.json_output:
            print(json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
        else:
            print("=== Synthèse du risque ===")
            summary = report.risk_summary()
            print(f"Niveau: {summary['niveau']} | Score: {summary['score']}")
            if report.email_result:
                print("\n--- Analyse Email ---")
                print(f"Score: {report.email_result['score']:.3f}")
                print(f"Label: {report.email_result['label']}")
                if report.email_result["indicators"]:
                    print("Indicateurs:", "; ".join(report.email_result["indicators"]))
                print(f"Modèle: {report.email_result['model_used']}")
            if report.url_results:
                print("\n--- Analyse URLs ---")
                for item in report.url_results:
                    print(f"{item['url']} -> {item['label']} ({item['score']:.3f})")
                    if item["indicators"]:
                        print("  Indicateurs:", "; ".join(item["indicators"]))
                    print(f"  Modèle: {item['model_used']}")
    elif args.command == "train":
        metrics = guardian.train_models(
            email_dataset=getattr(args, "email_dataset", None),
            url_dataset=getattr(args, "url_dataset", None),
        )
        print(json.dumps(metrics, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

