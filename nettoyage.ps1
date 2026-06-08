powershell -NoProfile -Command "
$phish='phishing_guardian'; $trade='trading_platform';
$dirs=@($phish,$trade,\"$phish/static\",\"$phish/templates\",\"$trade/static\",\"$trade/templates\")
$dirs|%{New-Item -ItemType Directory -Force -Path $_|Out-Null}

# Phishing Guardian
$phishFiles=@('phishing_guardian.py','gui_phishing_guardian.py','web_phishing_guardian.py','osint_scanner.py','vulnerability_scanner.py','advanced_vulnerability_scanner.py')
$phishFiles|%{if(Test-Path $_){Move-Item -Force $_ \"$phish/\"}}
' skiptracer_repo','exiftool'|%{if(Test-Path $_){Move-Item -Force $_ \"$phish/\"}}
'static/app.js','static/matrix.js','static/styles.css'|%{if(Test-Path $_){Move-Item -Force $_ \"$phish/static/\"}}
if(Test-Path 'templates/index.html'){Move-Item -Force 'templates/index.html' \"$phish/templates/\"}

# Trading Analyzer
$tradeItems=@(
'.mt5_config.json','accounts_config.json','activate_symbols.py','check_symbols.py','config_api.py','config_demo_account.py','config_exness_auto.py','config_mt5_interactif.py','force_reconnect_demo.py','load_all_data.py','debug_data.py','diagnose_connection.py','reconnect_demo.py','run_trading_app.py','setup_mt5_simple.py','setup_mt5.py','switch_to_demo.py','update_demo_account.py','env.example','EXNESS_SETUP.md','CONFIGURATION_AUTOMATIQUE.md','CONFIGURER_MT5.md','GUIDE_API_CONNEXION.md','GUIDE_VISUEL_TALIB.md','INSTALL_SIMPLE.md','INSTALL.md','install_talib_alternative.md','install_talib_python312.md','TELECHARGER_TALIB.md','TROUVER_API_EXNESS.md','TRADING_README.md','README.md','dummy','trading_analyzer','trading_web','requirements.txt'
)
$tradeItems|%{if(Test-Path $_){Move-Item -Force $_ \"$trade/\"}}
Get-ChildItem -File | Where-Object {$_.Name -like 'test_*'} | ForEach-Object {Move-Item -Force $_.FullName \"$trade/\"}
'static/auto_trading.js','static/trading_app.js','static/trading_styles.css','static/trading_styles_ultra.css'|%{if(Test-Path $_){Move-Item -Force $_ \"$trade/static/\"}}
if(Test-Path 'templates/trading_index.html'){Move-Item -Force 'templates/trading_index.html' \"$trade/templates/\"}

# Nettoyage des restes
foreach($f in @('test_create.txt','TEST.txt')){ if(Test-Path $f){ Remove-Item -Force $f } }
if((Test-Path 'static') -and -not (Get-ChildItem 'static')){ Remove-Item -Force 'static' }
if((Test-Path 'templates') -and -not (Get-ChildItem 'templates')){ Remove-Item -Force 'templates' }
"