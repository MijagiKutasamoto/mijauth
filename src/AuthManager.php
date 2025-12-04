<?php
/**
 * MijAuth - Authentication Manager
 * 
 * @package   MijAuth
 * @author    MijagiKutasamoto
 * @license   MIT
 */

declare(strict_types=1);

namespace MijAuth;

use MijAuth\Storage\UserStorageInterface;
use MijAuth\Storage\JsonFileStorage;

/**
 * High-level authentication manager that combines user storage with MijAuth
 */
class AuthManager
{
    private UserStorageInterface $storage;

    /**
     * @param UserStorageInterface|null $storage User storage implementation
     */
    public function __construct(?UserStorageInterface $storage = null)
    {
        $this->storage = $storage ?? new JsonFileStorage();
    }

    /**
     * Register a new user and generate their auth file
     * 
     * @param string $userId Unique user identifier
     * @param string $email User's email
     * @param string $password Plain text password (will be hashed)
     * @param string|null $deviceHash Optional device fingerprint
     * @return array{user: array, auth_file: string}
     */
    public function registerUser(
        string $userId,
        string $email,
        string $password,
        ?string $deviceHash = null
    ): array {
        $userKey = MijAuth::generateUserKey();
        $authResult = MijAuth::createAuthFile($userId, $userKey, $deviceHash);

        $user = [
            'id' => $userId,
            'email' => $email,
            'password_hash' => password_hash($password, PASSWORD_ARGON2ID),
            'encryption_key' => $userKey,
            'auth_token' => $authResult['token'],
            'created_at' => date('c')
        ];

        $this->storage->save($userId, $user);

        return [
            'user' => $user,
            'auth_file' => $authResult['file_content']
        ];
    }

    /**
     * Verify password (Step 1 of login)
     * 
     * @param string $email User's email
     * @param string $password Password to verify
     * @return array|null User data if password is valid, null otherwise
     */
    public function verifyPassword(string $email, string $password): ?array
    {
        $user = $this->storage->findByEmail($email);
        
        if ($user === null) {
            return null;
        }

        if (!password_verify($password, $user['password_hash'])) {
            return null;
        }

        return $user;
    }

    /**
     * Verify auth file (Step 2 of login)
     * 
     * @param string $userId User ID from step 1
     * @param string $fileContent Content of uploaded .mijauth file
     * @return bool
     */
    public function verifyAuthFile(string $userId, string $fileContent): bool
    {
        $user = $this->storage->findById($userId);
        
        if ($user === null) {
            return false;
        }

        return MijAuth::verifyAuthFileWithToken(
            $fileContent,
            $user['encryption_key'],
            $user['auth_token'],
            $user['id']
        );
    }

    /**
     * Complete two-factor login
     * 
     * @param string $email User's email
     * @param string $password Password
     * @param string $authFileContent Content of .mijauth file
     * @return array|null User data if login successful, null otherwise
     */
    public function login(string $email, string $password, string $authFileContent): ?array
    {
        // Step 1: Verify password
        $user = $this->verifyPassword($email, $password);
        if ($user === null) {
            return null;
        }

        // Step 2: Verify auth file
        if (!$this->verifyAuthFile($user['id'], $authFileContent)) {
            return null;
        }

        return $user;
    }

    /**
     * Regenerate auth file for a user (invalidates old file)
     * 
     * @param string $userId User ID
     * @param string|null $deviceHash Optional new device fingerprint
     * @return string|null New auth file content, or null if user not found
     */
    public function regenerateAuthFile(string $userId, ?string $deviceHash = null): ?string
    {
        $user = $this->storage->findById($userId);
        
        if ($user === null) {
            return null;
        }

        $authResult = MijAuth::regenerateAuthFile(
            $userId,
            $user['encryption_key'],
            $deviceHash
        );

        $this->storage->updateAuthToken($userId, $authResult['token']);

        return $authResult['file_content'];
    }

    /**
     * Get user by ID
     * 
     * @param string $userId
     * @return array|null
     */
    public function getUser(string $userId): ?array
    {
        return $this->storage->findById($userId);
    }

    /**
     * Get user by email
     * 
     * @param string $email
     * @return array|null
     */
    public function getUserByEmail(string $email): ?array
    {
        return $this->storage->findByEmail($email);
    }

    /**
     * Get the storage instance
     * 
     * @return UserStorageInterface
     */
    public function getStorage(): UserStorageInterface
    {
        return $this->storage;
    }
}
