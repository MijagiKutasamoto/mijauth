<?php
/**
 * MijAuth - User Storage Interface
 * 
 * @package   MijAuth
 * @author    MijagiKutasamoto
 * @license   MIT
 */

declare(strict_types=1);

namespace MijAuth\Storage;

/**
 * Interface for user storage implementations
 */
interface UserStorageInterface
{
    /**
     * Store user data
     * 
     * @param string $userId
     * @param array $userData
     * @return bool
     */
    public function save(string $userId, array $userData): bool;

    /**
     * Get user by ID
     * 
     * @param string $userId
     * @return array|null
     */
    public function findById(string $userId): ?array;

    /**
     * Get user by email
     * 
     * @param string $email
     * @return array|null
     */
    public function findByEmail(string $email): ?array;

    /**
     * Update user's auth token
     * 
     * @param string $userId
     * @param string $newToken
     * @return bool
     */
    public function updateAuthToken(string $userId, string $newToken): bool;

    /**
     * Delete user
     * 
     * @param string $userId
     * @return bool
     */
    public function delete(string $userId): bool;
}
