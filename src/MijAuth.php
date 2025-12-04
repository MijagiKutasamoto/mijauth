<?php
/**
 * MijAuth - File-Based Two-Factor Authentication System
 * 
 * @package   MijAuth
 * @author    MijagiKutasamoto
 * @license   MIT
 * @link      https://github.com/MijagiKutasamoto/mijauth
 */

declare(strict_types=1);

namespace MijAuth;

use RuntimeException;
use JsonException;

/**
 * Main MijAuth class for file-based 2FA authentication
 */
class MijAuth
{
    private const CIPHER = 'aes-256-gcm';
    private const KEY_LENGTH = 32; // 256 bits
    private const IV_LENGTH = 12;  // 96 bits for GCM
    private const TAG_LENGTH = 16; // 128 bits
    private const VERSION = 1;

    /**
     * Generate a new AES-256 key for a user
     * 
     * @return string Base64 encoded key
     * @throws RuntimeException If random bytes generation fails
     */
    public static function generateUserKey(): string
    {
        $key = random_bytes(self::KEY_LENGTH);
        return base64_encode($key);
    }

    /**
     * Generate a unique token for a user
     * 
     * @return string Hex encoded token
     */
    public static function generateToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Create an encrypted .mijauth authorization file
     * 
     * @param string $userId User identifier
     * @param string $userKeyBase64 User's encryption key in base64
     * @param string|null $deviceHash Optional device fingerprint hash
     * @return array{file_content: string, token: string}
     * @throws RuntimeException|JsonException
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
     * Verify an authorization file and return user data
     * 
     * @param string $fileContent Content of .mijauth file
     * @param string $userKeyBase64 User's encryption key in base64
     * @return array|null User data or null if verification failed
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
            
            // Validate structure
            if (!isset($payload['user_id'], $payload['token'], $payload['version'])) {
                return null;
            }

            return $payload;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Verify file and check if token matches the stored one
     * 
     * @param string $fileContent Content of .mijauth file
     * @param string $userKeyBase64 User's encryption key in base64
     * @param string $expectedToken Expected token from database
     * @param string $expectedUserId Expected user ID
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

        // Constant-time comparison to prevent timing attacks
        return hash_equals($expectedToken, $payload['token']) 
            && hash_equals($expectedUserId, $payload['user_id']);
    }

    /**
     * Regenerate authorization file (creates new token, invalidates old file)
     * 
     * @param string $userId User identifier
     * @param string $userKeyBase64 User's encryption key in base64
     * @param string|null $deviceHash Optional device fingerprint hash
     * @return array{file_content: string, token: string}
     */
    public static function regenerateAuthFile(
        string $userId,
        string $userKeyBase64,
        ?string $deviceHash = null
    ): array {
        return self::createAuthFile($userId, $userKeyBase64, $deviceHash);
    }

    /**
     * Generate a device hash based on available information
     * 
     * @param string $userAgent User-Agent header
     * @param string $acceptLanguage Accept-Language header
     * @param array $additionalData Additional data to include in hash
     * @return string SHA-256 hash of device info
     */
    public static function generateDeviceHash(
        string $userAgent = '',
        string $acceptLanguage = '',
        array $additionalData = []
    ): string {
        $data = array_merge([
            'user_agent' => $userAgent,
            'accept_language' => $acceptLanguage,
        ], $additionalData);

        return hash('sha256', json_encode($data));
    }

    /**
     * Generate device hash from current request (for web applications)
     * 
     * @return string SHA-256 hash of device info
     */
    public static function generateDeviceHashFromRequest(): string
    {
        return self::generateDeviceHash(
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''
        );
    }

    /**
     * Encrypt data using AES-256-GCM
     * 
     * @param string $plaintext Data to encrypt
     * @param string $keyBase64 Key in base64 format
     * @return string Base64 encoded encrypted data
     * @throws RuntimeException If encryption fails
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
            throw new RuntimeException('Encryption failed: ' . openssl_error_string());
        }

        // Format: IV (12 bytes) + Tag (16 bytes) + Ciphertext
        $combined = $iv . $tag . $ciphertext;
        
        return base64_encode($combined);
    }

    /**
     * Decrypt data using AES-256-GCM
     * 
     * @param string $encryptedBase64 Base64 encoded encrypted data
     * @param string $keyBase64 Key in base64 format
     * @return string|null Decrypted data or null on failure
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
     * Get the current library version
     * 
     * @return int
     */
    public static function getVersion(): int
    {
        return self::VERSION;
    }
}
