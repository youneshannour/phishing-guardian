# Extension navigateur — Phishing Guardian

Extension **Manifest V3** pour Chrome / Edge / Brave, connectée à l'API locale Phishing Guardian.

## Prérequis

1. Lancer le serveur : `lancer_web.bat` (http://127.0.0.1:8000)
2. Navigateur Chromium récent

## Installation (mode développeur)

1. Ouvrez `chrome://extensions` (ou `edge://extensions`)
2. Activez **Mode développeur**
3. Cliquez **Charger l'extension non empaquetée**
4. Sélectionnez le dossier `extension/` de ce projet

## Utilisation

| Action | Comment |
|--------|---------|
| Popup | Clic sur l'icône 🛡 dans la barre d'outils |
| Analyser l'URL | Bouton « Analyser URL page » (détection phishing) |
| OSINT rapide | Saisir email/domaine/IP/pseudo → **Playbook rapide** |
| Menu contextuel | Clic droit → OSINT sur la sélection / URL / Ouvrir dashboard |

## Configuration

- **API locale** : par défaut `http://127.0.0.1:8000` (modifiable dans le popup)
- Variable serveur optionnelle : `PG_PUBLIC_URL` si l'API est exposée ailleurs
- CORS : activé par défaut (`CORS_ORIGINS=*`)

## Fichiers

| Fichier | Rôle |
|---------|------|
| `manifest.json` | Configuration MV3 |
| `background.js` | Menus contextuels, messages API |
| `popup.html/js/css` | Interface popup |
| `content.js` | Détection de sélection sur la page |

## API utilisées

- `GET /api/health` — statut connexion
- `POST /api/analyze` — analyse phishing URL
- `POST /api/playbooks/run` — investigation OSINT complète
- `GET /api/extension/status` — métadonnées extension
