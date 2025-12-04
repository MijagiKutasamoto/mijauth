<?php
/**
 * MijAuth - System Weryfikacji Dwuetapowej (2FA) oparty na plikach
 * Implementacja PHP
 * 
 * Wymaga PHP 7.4+ z rozszerzeniem OpenSSL
 */

class MijAuth
{
    private const CIPHER = 'aes-256-gcm';
    private const KEY_LENGTH = 32; // 256 bits
    private const IV_LENGTH = 12;  // 96 bits dla GCM
    private const TAG_LENGTH = 16; // 128 bits
    private const VERSION = 1;

    /**
     * Generuje nowy klucz AES-256 dla użytkownika
     * @return string Klucz w formacie base64
     */
    public static function generateUserKey(): string
    {
        $key = random_bytes(self::KEY_LENGTH);
        return base64_encode($key);
    }

    /**
     * Generuje unikalny token dla użytkownika
     * @return string Token w formacie hex
     */
    public static function generateToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Tworzy zaszyfrowany plik autoryzacyjny .mijauth
     * 
     * @param string $userId Identyfikator użytkownika
     * @param string $userKeyBase64 Klucz użytkownika w base64
     * @param string|null $deviceHash Opcjonalny hash urządzenia
     * @return array ['file_content' => string, 'token' => string]
     */
    public static function createAuthFile(
        string $userId,
        string $userKeyBase64,
        ?string $deviceHash = null
    ): array {
        $token = self::generateToken();
        
        $payload = [
            'user_id' => $userId,
            'token' => $token,
            'created_at' => date('c'),
            'device_hash' => $deviceHash,
            'version' => self::VERSION
        ];

        $jsonPayload = json_encode($payload, JSON_THROW_ON_ERROR);
        $encryptedContent = self::encrypt($jsonPayload, $userKeyBase64);

        return [
            'file_content' => $encryptedContent,
            'token' => $token
        ];
    }

    /**
     * Weryfikuje plik autoryzacyjny i zwraca dane użytkownika
     * 
     * @param string $fileContent Zawartość pliku .mijauth
     * @param string $userKeyBase64 Klucz użytkownika w base64
     * @return array|null Dane użytkownika lub null jeśli weryfikacja nie powiodła się
     */
    public static function verifyAuthFile(
        string $fileContent,
        string $userKeyBase64
    ): ?array {
        try {
            $decrypted = self::decrypt($fileContent, $userKeyBase64);
            
            if ($decrypted === null) {
                return null;
            }

            $payload = json_decode($decrypted, true, 512, JSON_THROW_ON_ERROR);
            
            // Walidacja struktury
            if (!isset($payload['user_id'], $payload['token'], $payload['version'])) {
                return null;
            }

            return $payload;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Weryfikuje plik i sprawdza czy token zgadza się z przechowywanym
     * 
     * @param string $fileContent Zawartość pliku .mijauth
     * @param string $userKeyBase64 Klucz użytkownika w base64
     * @param string $expectedToken Oczekiwany token z bazy danych
     * @param string $expectedUserId Oczekiwane ID użytkownika
     * @return bool
     */
    public static function verifyAuthFileWithToken(
        string $fileContent,
        string $userKeyBase64,
        string $expectedToken,
        string $expectedUserId
    ): bool {
        $payload = self::verifyAuthFile($fileContent, $userKeyBase64);
        
        if ($payload === null) {
            return false;
        }

        // Weryfikacja z constant-time comparison
        return hash_equals($expectedToken, $payload['token']) 
            && hash_equals($expectedUserId, $payload['user_id']);
    }

    /**
     * Regeneruje plik autoryzacyjny (nowy token)
     * Stary plik zostanie automatycznie unieważniony
     * 
     * @param string $userId Identyfikator użytkownika
     * @param string $userKeyBase64 Klucz użytkownika w base64
     * @param string|null $deviceHash Opcjonalny hash urządzenia
     * @return array ['file_content' => string, 'token' => string]
     */
    public static function regenerateAuthFile(
        string $userId,
        string $userKeyBase64,
        ?string $deviceHash = null
    ): array {
        // Po prostu tworzymy nowy plik z nowym tokenem
        return self::createAuthFile($userId, $userKeyBase64, $deviceHash);
    }

    /**
     * Szyfruje dane przy użyciu AES-256-GCM
     * 
     * @param string $plaintext Dane do zaszyfrowania
     * @param string $keyBase64 Klucz w formacie base64
     * @return string Zaszyfrowane dane w formacie base64
     */
    private static function encrypt(string $plaintext, string $keyBase64): string
    {
        $key = base64_decode($keyBase64);
        $iv = random_bytes(self::IV_LENGTH);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed');
        }

        // Format: IV (12 bytes) + Tag (16 bytes) + Ciphertext
        $combined = $iv . $tag . $ciphertext;
        
        return base64_encode($combined);
    }

    /**
     * Odszyfrowuje dane przy użyciu AES-256-GCM
     * 
     * @param string $encryptedBase64 Zaszyfrowane dane w formacie base64
     * @param string $keyBase64 Klucz w formacie base64
     * @return string|null Odszyfrowane dane lub null przy błędzie
     */
    private static function decrypt(string $encryptedBase64, string $keyBase64): ?string
    {
        $key = base64_decode($keyBase64);
        $combined = base64_decode($encryptedBase64);

        if (strlen($combined) < self::IV_LENGTH + self::TAG_LENGTH) {
            return null;
        }

        $iv = substr($combined, 0, self::IV_LENGTH);
        $tag = substr($combined, self::IV_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($combined, self::IV_LENGTH + self::TAG_LENGTH);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return $plaintext !== false ? $plaintext : null;
    }

    /**
     * Generuje hash urządzenia na podstawie dostępnych informacji
     * 
     * @return string Hash urządzenia
     */
    public static function generateDeviceHash(): string
    {
        $data = [
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            // Możesz dodać więcej fingerprinting
        ];

        return hash('sha256', json_encode($data));
    }
}

/**
 * Symulacja bazy danych użytkowników
 */
class UserDatabase
{
    private array $users = [];
    private string $storageFile;

    public function __construct(string $storageFile = 'users.json')
    {
        $this->storageFile = $storageFile;
        $this->load();
    }

    private function load(): void
    {
        if (file_exists($this->storageFile)) {
            $this->users = json_decode(file_get_contents($this->storageFile), true) ?? [];
        }
    }

    private function save(): void
    {
        file_put_contents($this->storageFile, json_encode($this->users, JSON_PRETTY_PRINT));
    }

    public function createUser(string $userId, string $email, string $passwordHash): array
    {
        $userKey = MijAuth::generateUserKey();
        $authResult = MijAuth::createAuthFile($userId, $userKey);

        $this->users[$userId] = [
            'id' => $userId,
            'email' => $email,
            'password_hash' => $passwordHash,
            'encryption_key' => $userKey,
            'auth_token' => $authResult['token'],
            'created_at' => date('c')
        ];

        $this->save();

        return [
            'user' => $this->users[$userId],
            'auth_file' => $authResult['file_content']
        ];
    }

    public function getUser(string $userId): ?array
    {
        return $this->users[$userId] ?? null;
    }

    public function getUserByEmail(string $email): ?array
    {
        foreach ($this->users as $user) {
            if ($user['email'] === $email) {
                return $user;
            }
        }
        return null;
    }

    public function updateAuthToken(string $userId, string $newToken): void
    {
        if (isset($this->users[$userId])) {
            $this->users[$userId]['auth_token'] = $newToken;
            $this->save();
        }
    }
}
