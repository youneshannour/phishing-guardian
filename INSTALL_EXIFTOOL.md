# Installation ExifTool sur Windows

## Méthode 1 : Installation dans le PATH (Recommandé)

1. **Télécharger ExifTool** :
   - Aller sur https://exiftool.org/
   - Télécharger `exiftool-XX.XX_64.zip` (version Windows)

2. **Extraire le fichier** :
   - Extraire le ZIP
   - Vous obtiendrez un dossier `exiftool-XX.XX_64`

3. **Renommer et déplacer** :
   - Dans le dossier, renommer `exiftool(-k).exe` en `exiftool.exe`
   - Copier `exiftool.exe` et le dossier `exiftool_files` dans `C:\Windows\` (ou un autre dossier dans votre PATH)

4. **Vérifier l'installation** :
   ```powershell
   exiftool -ver
   ```
   Vous devriez voir la version affichée.

## Méthode 2 : Installation locale (Plus simple)

1. **Télécharger et extraire** comme ci-dessus

2. **Créer un dossier dans le projet** :
   ```powershell
   mkdir exiftool
   ```

3. **Copier les fichiers** :
   - Copier `exiftool.exe` (renommé) dans `C:\Users\Younes\Downloads\projetPython\exiftool\`
   - Copier le dossier `exiftool_files` dans le même emplacement

4. **Le code détectera automatiquement** ExifTool dans ce dossier

## Vérification

Après installation, redémarrez le serveur et testez l'onglet EXIF dans l'interface web.

