# Password Manager Flask - Versione Crittografata

Un gestore di password sicuro sviluppato in Python con Flask e crittografia avanzata.

## Caratteristiche di Sicurezza

- **Crittografia PBKDF2 con SHA512**: Tutte le password salvate sono crittografate usando PBKDF2 con 100.000 iterazioni
- **Salt unici**: Ogni utente ha un salt unico per la derivazione della chiave
- **Chiave master derivata**: La chiave di crittografia è derivata dalla password dell'utente
- **Hash sicuri**: Password degli utenti hashate con Werkzeug (bcrypt)
- **Sessioni sicure**: Autenticazione basata su sessioni Flask

## Algoritmi di Crittografia

### PBKDF2 con SHA512
- **Algoritmo**: PBKDF2 (Password-Based Key Derivation Function 2)
- **Hash**: SHA512
- **Iterazioni**: 100.000 (raccomandato OWASP)
- **Lunghezza chiave**: 256 bit (32 byte)
- **Salt**: 256 bit casuali per utente

### Fernet (AES 128)
- **Crittografia simmetrica**: AES 128 in modalità CBC
- **HMAC**: SHA256 per l'autenticazione
- **Padding**: PKCS7
- **IV**: Generato casualmente per ogni crittografia

## Installazione

1. Avviare il programma Start.vbs
