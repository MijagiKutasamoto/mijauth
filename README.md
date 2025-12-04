# MijAuth - File-Based Two-Factor Authentication System (2FA)

[🇵🇱 Polski](#polski) | [🇬🇧 English](#english)

---

<a name="english"></a>
## 🇬🇧 English

### Description

MijAuth is a two-factor authentication system that uses encrypted files as the second authentication factor. Instead of SMS codes or TOTP apps, the user stores a special `.mijauth` file that must be uploaded during login.

### How Does It Work?

#### 1. User Registration
- User registers in the system
- System generates a unique AES-256 key for the user
- System creates an authorization file `.mijauth` containing encrypted data:
  - User ID
  - Unique token
  - Creation timestamp
  - Hardware hash (optional)
- User downloads the file and stores it securely

#### 2. Login Process
1. User enters login and password (first factor)
2. System requests the `.mijauth` file (second factor)
3. System decrypts the file using user's key
4. Verifies if the data in the file matches the database
5. If everything is OK - user is logged in

#### 3. Structure of .mijauth File

The file contains JSON data, encrypted with AES-256-GCM:
```json
{
  "user_id": "unique-user-identifier",
  "token": "random-256-bit-token",
  "created_at": "2024-01-01T00:00:00Z",
  "device_hash": "optional-device-fingerprint",
  "version": 1
}
```

### Security Features

| Feature | Description |
|---------|-------------|
| **AES-256-GCM** | Symmetric encryption with authentication |
| **Unique Keys** | Each user has their own encryption key |
| **IV/Nonce** | Random initialization vector for each file |
| **One-time Token** | Ability to invalidate and regenerate |
| **Integrity Verification** | GCM ensures data authenticity |
| **Constant-time Comparison** | Protection against timing attacks |

### Installation and Usage

#### PHP (Composer)

```bash
composer require mijagikutasamoto/mijauth
```

```php
<?php
require 'vendor/autoload.php';

use MijAuth\AuthManager;

// Initialize
$auth = new AuthManager();

// Register user
$result = $auth->registerUser('user123', 'email@example.com', 'password');
file_put_contents('user.mijauth', $result['auth_file']);

// Login
$fileContent = file_get_contents('user.mijauth');
$user = $auth->login('email@example.com', 'password', $fileContent);

if ($user) {
    echo "Login successful!";
}
```

#### PHP (Manual)
```bash
cd examples/php
php example.php
```

#### Node.js (JavaScript)
```bash
cd examples/nodejs
node example.js
```

#### .NET (C#)
```bash
cd examples/dotnet
dotnet run
```

#### Python
```bash
cd examples/python
pip install -r requirements.txt
python example.py
```

#### Go
```bash
cd examples/go
go run .
```

#### Ruby
```bash
cd examples/ruby
ruby example.rb
```

### API Reference

Each implementation provides the same methods:

| Method | Description |
|--------|-------------|
| `generateUserKey()` | Generates an AES-256 key for the user |
| `createAuthFile(userData, key)` | Creates an encrypted .mijauth file |
| `verifyAuthFile(fileContent, key)` | Verifies the file and returns user data |
| `verifyAuthFileWithToken(...)` | Verifies file against stored token |
| `regenerateAuthFile(userId, key)` | Generates a new file (invalidates old one) |

### Integration Example

```
1. User registers → System generates key and .mijauth file
2. User logs in with password → System requests file
3. User uploads file → System verifies
4. Success → Access granted
```

### Web Integration Example (Node.js/Express)

```javascript
const express = require('express');
const multer = require('multer');
const { MijAuth, UserDatabase } = require('./MijAuth');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// Step 1: Password verification
app.post('/login/step1', (req, res) => {
    const { email, password } = req.body;
    const user = db.getUserByEmail(email);
    
    if (user && db.verifyPassword(user, password)) {
        req.session.pendingUserId = user.id;
        res.json({ success: true, require2FA: true });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Step 2: File verification
app.post('/login/step2', upload.single('authFile'), (req, res) => {
    const userId = req.session.pendingUserId;
    const user = db.getUser(userId);
    const fileContent = req.file.buffer.toString('utf8');
    
    if (MijAuth.verifyAuthFileWithToken(
        fileContent, 
        user.encryption_key,
        user.auth_token, 
        user.id
    )) {
        req.session.authenticated = true;
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Invalid auth file' });
    }
});
```

### Advantages

- ✅ Works offline (no SMS/internet needed for code generation)
- ✅ File can be stored on USB, cloud, or phone
- ✅ Easy integration with existing systems
- ✅ Ability to create multiple files for different devices
- ✅ Full user control over the second factor
- ✅ Cross-platform compatibility
- ✅ No third-party dependencies for core functionality

### Limitations

- ⚠️ File can be copied (unlike hardware keys)
- ⚠️ User must securely store the file
- ⚠️ Requires file upload on each login
- ⚠️ Not suitable for mobile-first applications

### Security Recommendations

1. **Store the file securely** - Use encrypted storage (USB with encryption, password manager)
2. **Create backup files** - Generate files for multiple devices
3. **Regenerate periodically** - Create new files every few months
4. **Monitor access** - Log all 2FA verification attempts
5. **Combine with other factors** - Use together with password and optionally biometrics

### Technical Specifications

| Parameter | Value |
|-----------|-------|
| Encryption Algorithm | AES-256-GCM |
| Key Length | 256 bits (32 bytes) |
| IV/Nonce Length | 96 bits (12 bytes) |
| Authentication Tag | 128 bits (16 bytes) |
| Token Length | 256 bits (32 bytes, hex encoded) |
| File Format | Base64 encoded binary |

---

<a name="polski"></a>
## 🇵🇱 Polski

### Opis

MijAuth to system weryfikacji dwuetapowej, który wykorzystuje zaszyfrowane pliki jako drugi czynnik uwierzytelniania. Zamiast kodów SMS lub aplikacji TOTP, użytkownik przechowuje specjalny plik `.mijauth`, który musi przesłać podczas logowania.

### Jak to działa?

#### 1. Rejestracja użytkownika
- Użytkownik rejestruje się w systemie
- System generuje unikalny klucz AES-256 dla użytkownika
- System tworzy plik autoryzacyjny `.mijauth` zawierający zaszyfrowane dane:
  - ID użytkownika
  - Unikalny token
  - Timestamp utworzenia
  - Hash sprzętowy (opcjonalnie)
- Użytkownik pobiera plik i przechowuje go bezpiecznie

#### 2. Proces logowania
1. Użytkownik wpisuje login i hasło (pierwszy czynnik)
2. System prosi o przesłanie pliku `.mijauth` (drugi czynnik)
3. System odszyfrowuje plik kluczem użytkownika
4. Weryfikuje czy dane w pliku zgadzają się z bazą danych
5. Jeśli wszystko OK - użytkownik zostaje zalogowany

#### 3. Struktura pliku .mijauth

Plik zawiera dane w formacie JSON, zaszyfrowane AES-256-GCM:
```json
{
  "user_id": "unikalny-identyfikator-użytkownika",
  "token": "losowy-256-bitowy-token",
  "created_at": "2024-01-01T00:00:00Z",
  "device_hash": "opcjonalny-odcisk-urządzenia",
  "version": 1
}
```

### Funkcje bezpieczeństwa

| Funkcja | Opis |
|---------|------|
| **AES-256-GCM** | Szyfrowanie symetryczne z uwierzytelnieniem |
| **Unikalne klucze** | Każdy użytkownik ma własny klucz szyfrowania |
| **IV/Nonce** | Losowy wektor inicjalizacji dla każdego pliku |
| **Token jednorazowy** | Możliwość unieważnienia i regeneracji |
| **Weryfikacja integralności** | GCM zapewnia autentyczność danych |
| **Porównanie w stałym czasie** | Ochrona przed atakami czasowymi |

### Instalacja i użycie

#### PHP (Composer)

```bash
composer require mijagikutasamoto/mijauth
```

```php
<?php
require 'vendor/autoload.php';

use MijAuth\AuthManager;

// Inicjalizacja
$auth = new AuthManager();

// Rejestracja użytkownika
$result = $auth->registerUser('user123', 'email@example.com', 'haslo');
file_put_contents('user.mijauth', $result['auth_file']);

// Logowanie
$fileContent = file_get_contents('user.mijauth');
$user = $auth->login('email@example.com', 'haslo', $fileContent);

if ($user) {
    echo "Logowanie udane!";
}
```

#### PHP (Ręcznie)
```bash
cd examples/php
php example.php
```

#### Node.js (JavaScript)
```bash
cd examples/nodejs
node example.js
```

#### .NET (C#)
```bash
cd examples/dotnet
dotnet run
```

#### Python
```bash
cd examples/python
pip install -r requirements.txt
python example.py
```

#### Go
```bash
cd examples/go
go run .
```

#### Ruby
```bash
cd examples/ruby
ruby example.rb
```

### Referencja API

Każda implementacja udostępnia te same metody:

| Metoda | Opis |
|--------|------|
| `generateUserKey()` | Generuje klucz AES-256 dla użytkownika |
| `createAuthFile(userData, key)` | Tworzy zaszyfrowany plik .mijauth |
| `verifyAuthFile(fileContent, key)` | Weryfikuje plik i zwraca dane użytkownika |
| `verifyAuthFileWithToken(...)` | Weryfikuje plik względem zapisanego tokenu |
| `regenerateAuthFile(userId, key)` | Generuje nowy plik (unieważnia stary) |

### Przykład integracji

```
1. Użytkownik rejestruje się → System generuje klucz i plik .mijauth
2. Użytkownik loguje się hasłem → System prosi o plik
3. Użytkownik przesyła plik → System weryfikuje
4. Sukces → Dostęp przyznany
```

### Przykład integracji webowej (PHP)

```php
<?php
require_once 'MijAuth.php';

session_start();
$db = new UserDatabase();

// Krok 1: Weryfikacja hasła
if ($_POST['action'] === 'login_step1') {
    $user = $db->getUserByEmail($_POST['email']);
    
    if ($user && password_verify($_POST['password'], $user['password_hash'])) {
        $_SESSION['pending_user_id'] = $user['id'];
        echo json_encode(['success' => true, 'require2FA' => true]);
    } else {
        http_response_code(401);
        echo json_encode(['error' => 'Nieprawidłowe dane']);
    }
}

// Krok 2: Weryfikacja pliku
if ($_POST['action'] === 'login_step2' && isset($_FILES['authFile'])) {
    $userId = $_SESSION['pending_user_id'];
    $user = $db->getUser($userId);
    $fileContent = file_get_contents($_FILES['authFile']['tmp_name']);
    
    if (MijAuth::verifyAuthFileWithToken(
        $fileContent,
        $user['encryption_key'],
        $user['auth_token'],
        $user['id']
    )) {
        $_SESSION['authenticated'] = true;
        unset($_SESSION['pending_user_id']);
        echo json_encode(['success' => true]);
    } else {
        http_response_code(401);
        echo json_encode(['error' => 'Nieprawidłowy plik autoryzacyjny']);
    }
}
```

### Zalety

- ✅ Działa offline (nie wymaga SMS/internetu do generowania kodów)
- ✅ Plik można przechowywać na USB, w chmurze lub na telefonie
- ✅ Łatwa integracja z istniejącymi systemami
- ✅ Możliwość tworzenia wielu plików dla różnych urządzeń
- ✅ Pełna kontrola użytkownika nad drugim czynnikiem
- ✅ Kompatybilność między platformami
- ✅ Brak zewnętrznych zależności dla podstawowej funkcjonalności

### Ograniczenia

- ⚠️ Plik można skopiować (w przeciwieństwie do kluczy sprzętowych)
- ⚠️ Użytkownik musi bezpiecznie przechowywać plik
- ⚠️ Wymaga przesłania pliku przy każdym logowaniu
- ⚠️ Nie nadaje się do aplikacji mobile-first

### Zalecenia bezpieczeństwa

1. **Przechowuj plik bezpiecznie** - Używaj zaszyfrowanego storage (USB z szyfrowaniem, menedżer haseł)
2. **Twórz kopie zapasowe** - Generuj pliki dla wielu urządzeń
3. **Regeneruj okresowo** - Twórz nowe pliki co kilka miesięcy
4. **Monitoruj dostęp** - Loguj wszystkie próby weryfikacji 2FA
5. **Łącz z innymi czynnikami** - Używaj razem z hasłem i opcjonalnie biometrią

### Specyfikacja techniczna

| Parametr | Wartość |
|----------|---------|
| Algorytm szyfrowania | AES-256-GCM |
| Długość klucza | 256 bitów (32 bajty) |
| Długość IV/Nonce | 96 bitów (12 bajtów) |
| Tag uwierzytelniający | 128 bitów (16 bajtów) |
| Długość tokenu | 256 bitów (32 bajty, kodowanie hex) |
| Format pliku | Binarny zakodowany Base64 |

---

## Project Structure / Struktura projektu

```
mijauth/
├── README.md                    # This documentation / Ta dokumentacja
└── examples/
    ├── php/
    │   ├── MijAuth.php          # Core library / Główna biblioteka
    │   └── example.php          # Usage example / Przykład użycia
    ├── nodejs/
    │   ├── MijAuth.js           # Core library / Główna biblioteka
    │   ├── example.js           # Usage example / Przykład użycia
    │   └── package.json
    ├── dotnet/
    │   ├── MijAuth.cs           # Core library / Główna biblioteka
    │   ├── Program.cs           # Usage example / Przykład użycia
    │   └── MijAuth.csproj
    ├── python/
    │   ├── mijauth.py           # Core library / Główna biblioteka
    │   ├── example.py           # Usage example / Przykład użycia
    │   └── requirements.txt
    ├── go/
    │   ├── mijauth.go           # Core library / Główna biblioteka
    │   ├── main.go              # Usage example / Przykład użycia
    │   └── go.mod
    └── ruby/
        ├── mijauth.rb           # Core library / Główna biblioteka
        └── example.rb           # Usage example / Przykład użycia
```

---

## License / Licencja

MIT License - Free to use in commercial and private projects.

MIT License - Swobodne użycie w projektach komercyjnych i prywatnych.

---

## Contributing / Współpraca

Contributions are welcome! Please feel free to submit a Pull Request.

Zapraszamy do współpracy! Możesz przesłać Pull Request.

---

## Author / Autor

Created with ❤️ for secure authentication.

Stworzone z ❤️ dla bezpiecznej autentykacji.
