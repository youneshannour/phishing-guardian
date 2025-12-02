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
    "suspension",
    "paiement",
    "invoice",
    "facture",
    "wire transfer",
    "password",
    "code",
    "verify",
    "otp",
    "alerte",
    "livraison",
    "votre compte sera suspendu",
    "votre compte va être suspendu",
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
        score = 0.15

        hits = [kw for kw in SUSPICIOUS_EMAIL_KEYWORDS if kw in lowered]
        if hits:
            indicators.append(f"Mots suspects détectés: {', '.join(set(hits))}")
            score += 0.2 * len(hits)

        # Formulations typiques de phishing en français
        if "votre compte sera suspendu" in lowered or "votre compte va être suspendu" in lowered:
            indicators.append("Menace explicite de suspension de compte")
            score += 0.25

        if re.search(r"https?://", lowered):
            indicators.append("Liens externes présents")
            score += 0.1

        if re.search(r"\b\d{6}\b", lowered):
            indicators.append("Codes OTP détectés")
            score += 0.1

        if "!" in text:
            indicators.append("Ponctuation agressive")
            score += 0.05

        if len(text) > 2000:
            indicators.append("Email très long (camouflage possible)")
            score += 0.05

        return {"score": min(score, 0.95), "indicators": indicators}

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
            label = "phishing" if result["score"] >= 0.5 else "legitime"
            result["label"] = label
        else:
            # En pur mode heuristique on accepte un seuil un peu plus bas
            result["label"] = "phishing" if result["score"] >= 0.5 else "legitime"

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

