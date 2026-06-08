import argparse
import json
import math
import re
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


SUSPICIOUS_EMAIL_KEYWORDS = [
    "urgent",
    "urgence",
    "urgente",
    "suspension",
    "suspendu",
    "suspendre",
    "paiement",
    "payment",
    "payer",
    "invoice",
    "facture",
    "wire transfer",
    "virement",
    "password",
    "mot de passe",
    "code",
    "verify",
    "vérifier",
    "vérification",
    "otp",
    "alerte",
    "alert",
    "livraison",
    "delivery",
    "votre compte sera suspendu",
    "votre compte va être suspendu",
    "cliquez ici",
    "click here",
    "cliquez maintenant",
    "agissez maintenant",
    "act now",
    "action requise",
    "action required",
    "confirmez",
    "confirm",
    "confirmation",
    "sécuriser",
    "secure",
    "sécurité",
    "security",
    "problème",
    "problem",
    "problème avec votre compte",
    "problem with your account",
    "accès",
    "access",
    "connexion",
    "login",
    "se connecter",
    "sign in",
    "identifiant",
    "credentials",
    "identifiants",
    "mise à jour",
    "update",
    "mettre à jour",
    "update your",
    "expire",
    "expiré",
    "expiration",
    "expire soon",
    "bientôt expiré",
    "gratuit",
    "free",
    "gagner",
    "win",
    "prix",
    "prize",
    "lottery",
    "loterie",
    "congratulations",
    "félicitations",
    "vous avez gagné",
    "you have won",
    "remboursement",
    "refund",
    "rembourser",
    "bitcoin",
    "crypto",
    "cryptocurrency",
    "investissement",
    "investment",
    "opportunité",
    "opportunity",
    "offre limitée",
    "limited offer",
    "offre spéciale",
    "special offer",
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
]

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
        lowered = text.lower()
        indicators = []
        score = 0.20  # Score de base plus élevé (plus méfiant)

        # Détection des mots-clés suspects (pondération améliorée)
        hits = [kw for kw in SUSPICIOUS_EMAIL_KEYWORDS if kw in lowered]
        if hits:
            unique_hits = list(set(hits))
            indicators.append(f"Mots suspects détectés: {', '.join(unique_hits[:5])}")
            # Plus de mots suspects = score plus élevé
            score += min(0.15 * len(unique_hits), 0.5)

        # Formulations typiques de phishing en français et anglais
        urgent_patterns = [
            r"votre compte sera suspendu",
            r"votre compte va être suspendu",
            r"your account will be suspended",
            r"account will be closed",
            r"votre compte sera fermé",
            r"action immédiate requise",
            r"immediate action required",
            r"agissez immédiatement",
            r"act immediately",
        ]
        for pattern in urgent_patterns:
            if re.search(pattern, lowered):
                indicators.append("Menace/Urgence explicite détectée")
                score += 0.3
                break

        # Détection de demandes d'argent/paiement
        money_patterns = [
            r"payer\s+(maintenant|immédiatement|aujourd'hui)",
            r"pay\s+(now|immediately|today)",
            r"virement\s+(urgent|immédiat)",
            r"wire\s+transfer",
            r"envoyer\s+de\s+l'argent",
            r"send\s+money",
            r"bitcoin|bitcoins",
            r"crypto.*monnaie",
            r"cryptocurrency",
        ]
        for pattern in money_patterns:
            if re.search(pattern, lowered):
                indicators.append("Demande de paiement/argent suspecte")
                score += 0.25
                break

        # Détection de liens suspects
        urls = re.findall(r"https?://[^\s\)]+", lowered)
        if urls:
            indicators.append(f"Liens externes présents ({len(urls)} lien(s))")
            score += 0.15
            
            # Vérifier si les URLs sont suspectes
            for url in urls:
                # URLs courtes (bit.ly, etc.) = suspect
                if re.search(r"(bit\.ly|tinyurl|t\.co|goo\.gl|short\.link)", url, re.I):
                    indicators.append("URL raccourcie détectée (très suspect)")
                    score += 0.2
                # IP dans l'URL = très suspect
                if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                    indicators.append("URL avec adresse IP (très suspect)")
                    score += 0.25
                # Domaines suspects
                if re.search(r"(\.tk|\.xyz|\.top|\.gq|\.ml|\.cf|\.ga)", url, re.I):
                    indicators.append("Domaine suspect détecté")
                    score += 0.2

        # Codes OTP/confirmation
        if re.search(r"\b\d{4,8}\b", lowered):
            indicators.append("Codes numériques détectés (OTP possible)")
            score += 0.15

        # Ponctuation agressive (plusieurs ! ou ?)
        exclamation_count = text.count('!')
        question_count = text.count('?')
        if exclamation_count >= 3 or question_count >= 3:
            indicators.append("Ponctuation excessive (signe d'urgence artificielle)")
            score += 0.1
        elif exclamation_count >= 1 or question_count >= 2:
            indicators.append("Ponctuation agressive")
            score += 0.05

        # Emails très courts (scams souvent courts et directs)
        if len(text) < 100:
            indicators.append("Email très court (pattern de scam)")
            score += 0.1
        # Emails très longs (camouflage)
        elif len(text) > 2000:
            indicators.append("Email très long (camouflage possible)")
            score += 0.1

        # Détection de fausses offres/gains
        scam_offers = [
            r"vous avez gagné",
            r"you have won",
            r"félicitations.*vous",
            r"congratulations.*you",
            r"gagner.*\d+.*euros?",
            r"win.*\d+.*dollars?",
            r"prix.*gratuit",
            r"free.*prize",
            r"loterie",
            r"lottery",
        ]
        for pattern in scam_offers:
            if re.search(pattern, lowered):
                indicators.append("Fausse offre/gain détecté")
                score += 0.3
                break

        # Détection de pressions psychologiques
        pressure_patterns = [
            r"dans les 24h",
            r"within 24 hours",
            r"dans les prochaines heures",
            r"in the next few hours",
            r"dernière chance",
            r"last chance",
            r"offre limitée",
            r"limited time",
            r"expire.*aujourd'hui",
            r"expires.*today",
        ]
        for pattern in pressure_patterns:
            if re.search(pattern, lowered):
                indicators.append("Pression temporelle artificielle")
                score += 0.2
                break

        # Détection de fautes d'orthographe suspectes (scams souvent mal écrits)
        common_words = ["votre", "vous", "compte", "email", "mot", "passe"]
        typo_count = 0
        for word in common_words:
            # Chercher des variations avec fautes
            if word in lowered:
                # Vérifier s'il y a des fautes autour
                pass
        # Si beaucoup de majuscules aléatoires = suspect
        if len(re.findall(r'[A-Z]{3,}', text)) > 3:
            indicators.append("Utilisation excessive de majuscules")
            score += 0.1

        return {"score": min(score, 0.98), "indicators": indicators}

    def assess(self, text: str) -> Dict[str, object]:
        text = _sanitize(text)
        result = {
            "label": "unknown",
            "score": 0.0,
            "indicators": [],
            "model_used": "heuristics",
        }

        heuristic = self._heuristic_score(text)
        result["score"] = heuristic["score"]
        result["indicators"] = heuristic["indicators"]

        if self.is_trained and self.pipeline:
            proba = float(self.pipeline.predict_proba([text])[0][1])
            result["model_used"] = "ml"
            result["score"] = max(result["score"], proba)
            # Classification avec seuils multiples pour plus de précision
            if result["score"] >= 0.4:
                label = "phishing"
            elif result["score"] >= 0.2:
                label = "suspect"  # Zone grise - méfiance recommandée
            else:
                label = "legitime"
            result["label"] = label
        else:
            # Classification avec seuils multiples en mode heuristique
            # Score >= 0.4 = phishing clair
            # Score 0.2-0.4 = suspect (méfiance recommandée)
            # Score < 0.2 = légitime
            if result["score"] >= 0.4:
                result["label"] = "phishing"
            elif result["score"] >= 0.2:
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

        # Cas typiques : combinaison de mots-clés très sensibles dans le domaine
        lowered = url.lower()
        if "paypal" in lowered and ("secure" in lowered or "login" in lowered):
            indicators.append("Imitation probable de PayPal")
            score += 0.25

        if not features["uses_https"]:
            indicators.append("Absence de HTTPS")
            score += 0.05

        if features["entropy"] > 4.3:
            indicators.append("Entropie élevée")
            score += 0.1

        if features["suspicious_tld"]:
            indicators.append("TLD douteux")
            score += 0.1

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
            result["label"] = "phishing" if result["score"] >= 0.5 else "legitime"
            result["model_used"] = "ml"
        else:
            # En pur mode heuristique on se montre un peu plus méfiant
            result["label"] = "phishing" if result["score"] >= 0.5 else "legitime"

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
        if email_text:
            report.email_result = self.email_detector.assess(email_text)
        if urls:
            report.url_results = [self.url_detector.assess(url) for url in urls]
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

