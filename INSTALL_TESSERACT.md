# Installation de Tesseract OCR pour Phishing Guardian

## Windows

### Option 1 : Installation automatique (recommandé)

1. Téléchargez Tesseract depuis : https://github.com/UB-Mannheim/tesseract/wiki
2. Installez le fichier `.exe` (ex: `tesseract-ocr-w64-setup-5.x.x.exe`)
3. **Important** : Pendant l'installation, cochez "Add to PATH" ou notez le chemin d'installation (par défaut: `C:\Program Files\Tesseract-OCR`)
4. Redémarrez le serveur Phishing Guardian

### Option 2 : Configuration manuelle du chemin

Si Tesseract n'est pas dans le PATH, ajoutez cette ligne au début de `web_phishing_guardian.py` :

```python
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
```

### Vérification

Pour vérifier que Tesseract est installé :

```powershell
tesseract --version
```

Ou dans Python :

```python
import pytesseract
print(pytesseract.get_tesseract_version())
```

## Langues supportées

Par défaut, l'OCR supporte le français et l'anglais (`fra+eng`).

Pour ajouter d'autres langues, téléchargez les fichiers de langue depuis :
https://github.com/tesseract-ocr/tessdata

Et placez-les dans le dossier `tessdata` de Tesseract (généralement `C:\Program Files\Tesseract-OCR\tessdata`).





