"""
Password Manager Flask Application - Versione Ottimizzata
=========================================================
Un gestore di password sicuro con crittografia end-to-end
"""

import os
import sqlite3
import secrets
import signal
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import base64
import random
import string

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


# Configurazione applicazione
class Config:
    """Configurazione centralizzata dell'applicazione"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'chiave-segreta-per-sessioni')
    DATABASE = 'password_manager.db'
    PBKDF2_ITERATIONS = 200000
    SALT_LENGTH = 32
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128


app = Flask(__name__)
app.secret_key = Config.SECRET_KEY


class CryptographyManager:
    """
    Gestisce la crittografia delle password utilizzando PBKDF2 con SHA512 e Fernet
    """
    
    @staticmethod
    def generate_salt() -> bytes:
        """Genera un salt casuale per PBKDF2"""
        return secrets.token_bytes(Config.SALT_LENGTH)
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Deriva una chiave utilizzando PBKDF2 con SHA512
        
        Args:
            password: Password in chiaro
            salt: Salt per la derivazione
            
        Returns:
            Chiave derivata codificata base64
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=Config.PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    @staticmethod
    def encrypt_password(password: str, master_key: bytes) -> str:
        """
        Crittografa una password usando Fernet
        
        Args:
            password: Password da crittografare
            master_key: Chiave master per la crittografia
            
        Returns:
            Password crittografata codificata base64
        """
        fernet = Fernet(master_key)
        encrypted_password = fernet.encrypt(password.encode())
        return base64.urlsafe_b64encode(encrypted_password).decode()
    
    @staticmethod
    def decrypt_password(encrypted_password: str, master_key: bytes) -> str:
        """
        Decrittografa una password usando Fernet
        
        Args:
            encrypted_password: Password crittografata
            master_key: Chiave master per la decrittografia
            
        Returns:
            Password in chiaro
            
        Raises:
            ValueError: Se la decrittografia fallisce
        """
        try:
            fernet = Fernet(master_key)
            encrypted_data = base64.urlsafe_b64decode(encrypted_password.encode())
            decrypted_password = fernet.decrypt(encrypted_data)
            return decrypted_password.decode()
        except Exception as e:
            raise ValueError("Impossibile decrittografare la password") from e


class PasswordGenerator:
    """Generatore di password sicure con opzioni configurabili"""
    
    SPECIAL_CHARS = "!@#$%&*"
    
    @classmethod
    def generate_secure_password(
        cls,
        length: int = 16,
        use_special_chars: bool = True,
        use_uppercase: bool = True,
        use_numbers: bool = True
    ) -> str:
        """
        Genera una password casuale sicura
        
        Args:
            length: Lunghezza della password (4-128)
            use_special_chars: Include caratteri speciali
            use_uppercase: Include lettere maiuscole
            use_numbers: Include numeri
            
        Returns:
            Password generata
        """
        # Validazione lunghezza
        length = max(4, min(length, Config.MAX_PASSWORD_LENGTH))
        
        # Costruzione set di caratteri
        chars = string.ascii_lowercase  # Sempre incluse le minuscole
        required_chars = [random.choice(string.ascii_lowercase)]
        
        if use_uppercase:
            chars += string.ascii_uppercase
            required_chars.append(random.choice(string.ascii_uppercase))
        
        if use_numbers:
            chars += string.digits
            required_chars.append(random.choice(string.digits))
        
        if use_special_chars:
            chars += cls.SPECIAL_CHARS
            required_chars.append(random.choice(cls.SPECIAL_CHARS))
        
        # Genera il resto della password
        remaining_length = length - len(required_chars)
        additional_chars = [random.choice(chars) for _ in range(remaining_length)]
        
        # Combina e mescola tutti i caratteri
        password_chars = required_chars + additional_chars
        random.shuffle(password_chars)
        
        return ''.join(password_chars)


class DatabaseManager:
    """Gestisce le operazioni del database"""
    
    @staticmethod
    def init_database() -> None:
        """Inizializza il database con le tabelle necessarie"""
        with sqlite3.connect(Config.DATABASE) as conn:
            cursor = conn.cursor()
            
            # Tabella utenti con salt per la crittografia
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS utenti (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    encryption_salt BLOB NOT NULL,
                    data_creazione TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabella password salvate con crittografia
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_salvate (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    utente_id INTEGER,
                    nome_sito TEXT NOT NULL,
                    username_sito TEXT NOT NULL,
                    password_sito_encrypted TEXT NOT NULL,
                    data_creazione TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    data_modifica TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (utente_id) REFERENCES utenti (id)
                )
            ''')
            
            conn.commit()
    
    @staticmethod
    def get_connection() -> sqlite3.Connection:
        """Ottiene una connessione al database con row factory"""
        conn = sqlite3.connect(Config.DATABASE)
        conn.row_factory = sqlite3.Row
        return conn


class UserManager:
    """Gestisce le operazioni sugli utenti"""
    
    @staticmethod
    def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
        """Recupera un utente dal database tramite username"""
        with DatabaseManager.get_connection() as conn:
            return conn.execute(
                'SELECT * FROM utenti WHERE username = ?', (username,)
            ).fetchone()
    
    @staticmethod
    def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
        """Recupera un utente dal database tramite ID"""
        with DatabaseManager.get_connection() as conn:
            return conn.execute(
                'SELECT * FROM utenti WHERE id = ?', (user_id,)
            ).fetchone()
    
    @staticmethod
    def create_user(username: str, password: str) -> bool:
        """
        Crea un nuovo utente nel database
        
        Returns:
            True se la creazione è riuscita, False altrimenti
        """
        try:
            password_hash = generate_password_hash(password)
            encryption_salt = CryptographyManager.generate_salt()
            
            with DatabaseManager.get_connection() as conn:
                conn.execute(
                    'INSERT INTO utenti (username, password_hash, encryption_salt) VALUES (?, ?, ?)',
                    (username, password_hash, encryption_salt)
                )
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    @staticmethod
    def get_master_key(user_id: int, password: str) -> bytes:
        """
        Ottiene la chiave master dell'utente per la crittografia
        
        Raises:
            ValueError: Se l'utente non viene trovato
        """
        user = UserManager.get_user_by_id(user_id)
        if not user:
            raise ValueError("Utente non trovato")
        
        return CryptographyManager.derive_key(password, user['encryption_salt'])


class PasswordService:
    """Servizio per la gestione delle password salvate"""
    
    @staticmethod
    def get_user_passwords(user_id: int, master_key: bytes) -> List[Dict]:
        """
        Recupera e decrittografa tutte le password di un utente
        
        Returns:
            Lista di dizionari con le password decrittografate
        """
        with DatabaseManager.get_connection() as conn:
            password_entries = conn.execute(
                'SELECT * FROM password_salvate WHERE utente_id = ? ORDER BY nome_sito',
                (user_id,)
            ).fetchall()
        
        decrypted_passwords = []
        for entry in password_entries:
            try:
                decrypted_password = CryptographyManager.decrypt_password(
                    entry['password_sito_encrypted'], master_key
                )
                decrypted_passwords.append({
                    'id': entry['id'],
                    'nome_sito': entry['nome_sito'],
                    'username_sito': entry['username_sito'],
                    'password_sito': decrypted_password,
                    'data_creazione': entry['data_creazione'],
                    'data_modifica': entry['data_modifica']
                })
            except ValueError:
                # Salta le password che non possono essere decrittografate
                continue
        
        return decrypted_passwords
    
    @staticmethod
    def add_password(user_id: int, site_name: str, site_username: str, 
                    site_password: str, master_key: bytes) -> bool:
        """Aggiunge una nuova password crittografata"""
        try:
            encrypted_password = CryptographyManager.encrypt_password(site_password, master_key)
            
            with DatabaseManager.get_connection() as conn:
                conn.execute(
                    'INSERT INTO password_salvate (utente_id, nome_sito, username_sito, password_sito_encrypted) VALUES (?, ?, ?, ?)',
                    (user_id, site_name, site_username, encrypted_password)
                )
                conn.commit()
            return True
        except Exception:
            return False
    
    @staticmethod
    def get_password_by_id(password_id: int, user_id: int) -> Optional[sqlite3.Row]:
        """Recupera una password specifica dell'utente"""
        with DatabaseManager.get_connection() as conn:
            return conn.execute(
                'SELECT * FROM password_salvate WHERE id = ? AND utente_id = ?',
                (password_id, user_id)
            ).fetchone()
    
    @staticmethod
    def update_password(password_id: int, user_id: int, site_name: str, 
                       site_username: str, site_password: str, master_key: bytes) -> bool:
        """Aggiorna una password esistente"""
        try:
            encrypted_password = CryptographyManager.encrypt_password(site_password, master_key)
            
            with DatabaseManager.get_connection() as conn:
                conn.execute(
                    'UPDATE password_salvate SET nome_sito = ?, username_sito = ?, password_sito_encrypted = ?, data_modifica = CURRENT_TIMESTAMP WHERE id = ? AND utente_id = ?',
                    (site_name, site_username, encrypted_password, password_id, user_id)
                )
                conn.commit()
            return True
        except Exception:
            return False
    
    @staticmethod
    def delete_password(password_id: int, user_id: int) -> bool:
        """Elimina una password"""
        try:
            with DatabaseManager.get_connection() as conn:
                conn.execute(
                    'DELETE FROM password_salvate WHERE id = ? AND utente_id = ?',
                    (password_id, user_id)
                )
                conn.commit()
            return True
        except Exception:
            return False


# Decoratori per l'autenticazione
def login_required(f):
    """Decoratore per richiedere l'autenticazione"""
    def decorated_function(*args, **kwargs):
        if 'utente_id' not in session or 'user_password' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function


# Route dell'applicazione
@app.route('/')
def index():
    """Pagina principale - reindirizza al login o dashboard"""
    if 'utente_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Gestisce il login degli utenti"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username e password sono obbligatori', 'error')
            return render_template('login.html')
        
        user = UserManager.get_user_by_username(username)
        
        if user and check_password_hash(user['password_hash'], password):
            session['utente_id'] = user['id']
            session['username'] = user['username']
            session['user_password'] = password  # Necessario per la decrittografia
            flash('Accesso effettuato con successo!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Username o password non validi', 'error')
    
    return render_template('login.html')


@app.route('/registrazione', methods=['GET', 'POST'])
def registrazione():
    """Gestisce la registrazione di nuovi utenti"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('conferma_password', '')
        
        # Validazioni
        if not username or not password:
            flash('Username e password sono obbligatori', 'error')
            return render_template('registrazione.html')
        
        if password != confirm_password:
            flash('Le password non corrispondono', 'error')
            return render_template('registrazione.html')
        
        if len(password) < Config.MIN_PASSWORD_LENGTH:
            flash(f'La password deve essere di almeno {Config.MIN_PASSWORD_LENGTH} caratteri', 'error')
            return render_template('registrazione.html')
        
        # Creazione utente
        if UserManager.create_user(username, password):
            flash('Registrazione completata! Ora puoi effettuare il login', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username già esistente', 'error')
    
    return render_template('registrazione.html')


@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard principale con elenco password"""
    try:
        master_key = UserManager.get_master_key(session['utente_id'], session['user_password'])
        password_list = PasswordService.get_user_passwords(session['utente_id'], master_key)
        
        return render_template('dashboard.html', password_salvate=password_list)
        
    except Exception as e:
        flash('Errore nell\'accesso alle password crittografate', 'error')
        return redirect(url_for('logout'))


@app.route('/aggiungi', methods=['GET', 'POST'])
@login_required
def aggiungi_password():
    """Aggiunge una nuova password"""
    form_data = {}
    password_generata = None
    
    if request.method == 'POST':
        # Gestione generazione password
        if 'genera_password' in request.form:
            length = int(request.form.get('lunghezza', 16))
            use_special_chars = 'caratteri_speciali' in request.form
            use_uppercase = 'usa_maiuscole' in request.form
            use_numbers = 'usa_numeri' in request.form
            
            password_generata = PasswordGenerator.generate_secure_password(
                length=length,
                use_special_chars=use_special_chars,
                use_uppercase=use_uppercase,
                use_numbers=use_numbers
            )
            
            form_data = {
                'nome_sito': request.form.get('nome_sito', ''),
                'username_sito': request.form.get('username_sito', ''),
                'password_sito': password_generata,
                'lunghezza': length,
                'caratteri_speciali': use_special_chars,
                'usa_maiuscole': use_uppercase,
                'usa_numeri': use_numbers
            }
            
            return render_template('aggiungi.html', form_data=form_data, password_generata=password_generata)
        
        # Gestione salvataggio password
        site_name = request.form.get('nome_sito', '').strip()
        site_username = request.form.get('username_sito', '').strip()
        site_password = request.form.get('password_sito', '')
        
        if not site_name or not site_username or not site_password:
            flash('Tutti i campi sono obbligatori', 'error')
            return render_template('aggiungi.html')
        
        try:
            master_key = UserManager.get_master_key(session['utente_id'], session['user_password'])
            
            if PasswordService.add_password(session['utente_id'], site_name, site_username, site_password, master_key):
                flash('Password aggiunta e crittografata con successo!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Errore durante il salvataggio della password', 'error')
                
        except Exception as e:
            flash('Errore nella crittografia della password', 'error')
    
    return render_template('aggiungi.html', form_data=form_data)


@app.route('/modifica/<int:password_id>', methods=['GET', 'POST'])
@login_required
def modifica_password(password_id):
    """Modifica una password esistente"""
    try:
        master_key = UserManager.get_master_key(session['utente_id'], session['user_password'])
        password_entry_raw = PasswordService.get_password_by_id(password_id, session['utente_id'])
        
        if not password_entry_raw:
            flash('Password non trovata', 'error')
            return redirect(url_for('dashboard'))
        
        # Decrittografia per la modifica
        password_decrypted = CryptographyManager.decrypt_password(
            password_entry_raw['password_sito_encrypted'], master_key
        )
        
        password_entry = {
            'id': password_entry_raw['id'],
            'nome_sito': password_entry_raw['nome_sito'],
            'username_sito': password_entry_raw['username_sito'],
            'password_sito': password_decrypted
        }
        
        if request.method == 'POST':
            site_name = request.form.get('nome_sito', '').strip()
            site_username = request.form.get('username_sito', '').strip()
            site_password = request.form.get('password_sito', '')
            
            if not site_name or not site_username or not site_password:
                flash('Tutti i campi sono obbligatori', 'error')
                return render_template('modifica.html', password_entry=password_entry)
            
            if PasswordService.update_password(password_id, session['utente_id'], site_name, site_username, site_password, master_key):
                flash('Password modificata e crittografata con successo!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Errore durante la modifica della password', 'error')
        
        return render_template('modifica.html', password_entry=password_entry)
        
    except Exception as e:
        flash('Errore nella gestione della password crittografata', 'error')
        return redirect(url_for('dashboard'))


@app.route('/elimina/<int:password_id>')
@login_required
def elimina_password(password_id):
    """Elimina una password"""
    if PasswordService.delete_password(password_id, session['utente_id']):
        flash('Password eliminata con successo!', 'success')
    else:
        flash('Errore durante l\'eliminazione della password', 'error')
    
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    """Effettua il logout pulendo la sessione"""
    session.clear()
    flash('Logout effettuato con successo', 'success')
    return redirect(url_for('login'))


@app.route('/cambia_password_master', methods=['GET', 'POST'])
@login_required
def cambia_password_master():
    """Cambia la password master dell'utente ri-crittografando tutte le password"""
    if request.method == 'POST':
        current_password = request.form.get('password_attuale', '')
        new_password = request.form.get('nuova_password', '')
        confirm_new_password = request.form.get('conferma_nuova_password', '')
        
        # Validazioni
        if new_password != confirm_new_password:
            flash('Le nuove password non corrispondono', 'error')
            return render_template('cambia_password.html')
        
        if len(new_password) < Config.MIN_PASSWORD_LENGTH:
            flash(f'La nuova password deve essere di almeno {Config.MIN_PASSWORD_LENGTH} caratteri', 'error')
            return render_template('cambia_password.html')
        
        # Verifica password attuale
        user = UserManager.get_user_by_id(session['utente_id'])
        if not user or not check_password_hash(user['password_hash'], current_password):
            flash('Password attuale non corretta', 'error')
            return render_template('cambia_password.html')
        
        try:
            # Processo di ri-crittografia
            old_master_key = UserManager.get_master_key(session['utente_id'], current_password)
            
            # Recupera e decrittografa tutte le password
            with DatabaseManager.get_connection() as conn:
                saved_passwords = conn.execute(
                    'SELECT * FROM password_salvate WHERE utente_id = ?',
                    (session['utente_id'],)
                ).fetchall()
                
                passwords_decrypted = []
                for row in saved_passwords:
                    password_decrypted = CryptographyManager.decrypt_password(
                        row['password_sito_encrypted'], old_master_key
                    )
                    passwords_decrypted.append({
                        'id': row['id'],
                        'password': password_decrypted
                    })
                
                # Genera nuovo salt e chiave
                new_salt = CryptographyManager.generate_salt()
                new_password_hash = generate_password_hash(new_password)
                new_master_key = CryptographyManager.derive_key(new_password, new_salt)
                
                # Aggiorna utente
                conn.execute(
                    'UPDATE utenti SET password_hash = ?, encryption_salt = ? WHERE id = ?',
                    (new_password_hash, new_salt, session['utente_id'])
                )
                
                # Ri-crittografa tutte le password
                for pwd_data in passwords_decrypted:
                    new_encrypted_password = CryptographyManager.encrypt_password(
                        pwd_data['password'], new_master_key
                    )
                    conn.execute(
                        'UPDATE password_salvate SET password_sito_encrypted = ? WHERE id = ?',
                        (new_encrypted_password, pwd_data['id'])
                    )
                
                conn.commit()
            
            # Aggiorna la sessione
            session['user_password'] = new_password
            
            flash('Password master cambiata con successo! Tutte le password sono state ri-crittografate.', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash('Errore durante il cambio password. Operazione annullata.', 'error')
            return render_template('cambia_password.html')
    
    return render_template('cambia_password.html')


@app.route('/genera_password', methods=['GET', 'POST'])
@login_required
def genera_password():
    """Pagina dedicata per la generazione di password"""
    password_generata = None

    if request.method == 'POST':
        length = int(request.form.get('lunghezza', 16))
        use_special_chars = request.form.get('caratteri_speciali') == 'on'
        use_uppercase = request.form.get('usa_maiuscole', 'on') == 'on'
        use_numbers = request.form.get('usa_numeri', 'on') == 'on'
        
        password_generata = PasswordGenerator.generate_secure_password(
            length=length,
            use_special_chars=use_special_chars,
            use_uppercase=use_uppercase,
            use_numbers=use_numbers
        )
        
    return render_template('genera_password.html', password=password_generata)


@app.route('/shutdown')
@login_required
def shutdown():
    """Spegne il server (solo per richieste locali)"""
    if request.remote_addr in ('127.0.0.1', 'localhost', '::1'):
        os.kill(os.getpid(), signal.SIGINT)
        return "Server in fase di spegnimento..."
    return "Operazione non permessa", 403


# Avvio dell'applicazione
if __name__ == '__main__':
    DatabaseManager.init_database()
    app.run(debug=True, host='127.0.0.1', port=5000)