<?php
/**
 * MijAuth - JSON File Storage Implementation
 * 
 * @package   MijAuth
 * @author    MijagiKutasamoto
 * @license   MIT
 */

declare(strict_types=1);

namespace MijAuth\Storage;

use RuntimeException;

/**
 * Simple JSON file-based storage for users
 * For production, use a database implementation
 */
class JsonFileStorage implements UserStorageInterface
{
    private string $filePath;
    private array $users = [];

    /**
     * @param string $filePath Path to JSON storage file
     */
    public function __construct(string $filePath = 'users.json')
    {
        $this->filePath = $filePath;
        $this->load();
    }

    /**
     * Load users from file
     */
    private function load(): void
    {
        if (file_exists($this->filePath)) {
            $content = file_get_contents($this->filePath);
            $this->users = json_decode($content, true) ?? [];
        }
    }

    /**
     * Save users to file
     */
    private function persist(): bool
    {
        $result = file_put_contents(
            $this->filePath,
            json_encode($this->users, JSON_PRETTY_PRINT)
        );
        return $result !== false;
    }

    /**
     * {@inheritdoc}
     */
    public function save(string $userId, array $userData): bool
    {
        $this->users[$userId] = $userData;
        return $this->persist();
    }

    /**
     * {@inheritdoc}
     */
    public function findById(string $userId): ?array
    {
        return $this->users[$userId] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function findByEmail(string $email): ?array
    {
        foreach ($this->users as $user) {
            if (($user['email'] ?? '') === $email) {
                return $user;
            }
        }
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function updateAuthToken(string $userId, string $newToken): bool
    {
        if (!isset($this->users[$userId])) {
            return false;
        }
        $this->users[$userId]['auth_token'] = $newToken;
        return $this->persist();
    }

    /**
     * {@inheritdoc}
     */
    public function delete(string $userId): bool
    {
        if (!isset($this->users[$userId])) {
            return false;
        }
        unset($this->users[$userId]);
        return $this->persist();
    }

    /**
     * Get all users
     * 
     * @return array
     */
    public function findAll(): array
    {
        return $this->users;
    }

    /**
     * Clear all users
     * 
     * @return bool
     */
    public function clear(): bool
    {
        $this->users = [];
        return $this->persist();
    }
}
