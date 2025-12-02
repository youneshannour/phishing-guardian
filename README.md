# OSINT Scanner

Un outil d'OSINT (Open Source Intelligence) qui automatise la découverte d'informations en utilisant Shodan et VirusTotal.

## Fonctionnalités

- Recherche d'informations via Shodan
- Vérification d'adresses IP sur VirusTotal
- Interface en ligne de commande colorée et intuitive
- Affichage des résultats dans des tableaux formatés
- **Phishing Guardian** : détection intelligente d'emails frauduleux et d'URLs suspectes (heuristiques + ML)

## Prérequis

- Python 3.7+
- Clés API pour Shodan et VirusTotal

## Installation

1. Clonez ce dépôt :
```bash
git clone <votre-repo>
cd <votre-repo>
```

2. Installez les dépendances :
```bash
pip install -r requirements.txt
```

3. Créez un fichier `.env` à partir du fichier `.env.example` :
```bash
cp .env.example .env
```

4. Modifiez le fichier `.env` et ajoutez vos clés API :
```
SHODAN_API_KEY=votre_clé_api_shodan
VIRUSTOTAL_API_KEY=votre_clé_api_virustotal
```

## Utilisation

Exécutez le scanner OSINT :
```bash
python osint_scanner.py
```

Le menu principal vous permettra de :
1. Effectuer une recherche sur Shodan
2. Vérifier une adresse IP sur VirusTotal
3. Quitter l'application

## Phishing Guardian – Détection proactive

### Installation spécifique

1. Assurez-vous d'avoir installé les dépendances (voir `requirements.txt`).
2. Préparez vos jeux de données :
   - `data/phishing_emails.csv` avec les colonnes `text,label`
   - `data/phishing_urls.csv` avec les colonnes `url,label`

### Entraîner les modèles ML
```bash
python phishing_guardian.py train --email-dataset data/phishing_emails.csv --url-dataset data/phishing_urls.csv
```

Les modèles sont sauvegardés dans `artifacts/`.

### Analyser un email / une URL
```bash
python phishing_guardian.py analyze --email "Votre compte sera suspendu..." --urls "http://login-update.example,https://secure-paypal.com.verify.co"
```

Options :
- `--json-output` pour un rapport JSON
- `--urls` accepte une liste JSON (`'[ "...", "..." ]'`) ou un fichier `.json`

### Fonctionnement
- Heuristiques avancées même sans modèle entraîné (entropie, TLD douteux, mots clés, IP dans l'URL…)
- Pipelines ML scikit-learn (TF-IDF, n-grammes, régression logistique)
- Rapport synthétique avec niveau de risque (`faible`, `modere`, `eleve`, `critique`)

### Interface graphique (GUI)

Pour lancer l'interface graphique de Phishing Guardian :

```bash
python gui_phishing_guardian.py
```

L'interface permet de :
- saisir le contenu d'un email,
- saisir une liste d'URLs séparées par des virgules,
- afficher un résumé de risque coloré et le détail des indicateurs pour l'email et chaque URL.

## Interface Web (site)

### Lancer l'appli web

1. Installer les dépendances (si ce n'est pas déjà fait) :
   ```bash
   pip install -r requirements.txt
   ```
2. Lancer le serveur FastAPI avec Uvicorn :
   ```bash
   uvicorn web_phishing_guardian:app --reload
   ```
3. Ouvrir votre navigateur sur :
   - `http://127.0.0.1:8000`

### Fonctionnalités de l'interface web

- Page unique moderne (Tailwind CSS, mode sombre) :
  - zone pour coller un email suspect,
  - champ pour saisir une liste d'URLs,
  - bouton “Analyser” qui appelle l'API `/api/analyze`.
- Résumé visuel du risque global :
  - badge de couleur selon le niveau (`faible`, `modere`, `eleve`, `critique`),
  - score global affiché.
- Détails par entité :
  - section email avec score, label et indicateurs détectés,
  - section URLs listant chaque URL, son label, son score et ses indicateurs.

## Exemples de requêtes Shodan

- `port:80 country:FR` : Recherche les serveurs web en France
- `product:nginx` : Recherche les serveurs utilisant Nginx
- `org:"Google"` : Recherche les systèmes appartenant à Google

## Sécurité

- Ne partagez jamais vos clés API
- Respectez les conditions d'utilisation de Shodan et VirusTotal
- Utilisez cet outil de manière éthique et légale

## Licence

MIT 