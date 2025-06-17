@echo off
:: Controllo installazione Python
python --version >nul 2>&1
if errorlevel 1 (
    msg * "❌ Python non è installato o non è nel PATH. Installa Python 3.7+ da https://python.org"
    exit /b 1
)

:: Installazione dipendenze (silenzioso)
python -m pip install --upgrade pip >nul 2>&1
python -m pip install tk aiohttp>=3.8.0 -r requirements.txt >nul 2>&1

:: Verifica se il file .db esiste PRIMA di avviare il server
set "REDIRECT_URL=http://localhost:5000/registrazione"
if exist "password_manager.db" (
    set "REDIRECT_URL=http://localhost:5000/login"
)

:: Creazione di un file VBS per avvio silenzioso
echo Set WshShell = CreateObject("WScript.Shell") > "%temp%\silent_flask.vbs"
echo WshShell.Run "python app.py", 0, False >> "%temp%\silent_flask.vbs"

:: Avvio dell'app in modalità completamente silenziosa
cscript //nologo "%temp%\silent_flask.vbs" >nul 2>&1

:: Pulizia del file temporaneo
del "%temp%\silent_flask.vbs" >nul 2>&1


:: Apertura del browser con il link corretto
start "" %REDIRECT_URL%

:: Chiusura automatica della finestra cmd
exit /b 0