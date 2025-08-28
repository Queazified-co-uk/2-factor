package com.queazified.velocity2fa;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.slf4j.Logger;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class TwoFactorManager {
    
    private final Path dataDirectory;
    private final Logger logger;
    private final GoogleAuthenticator authenticator;
    private final Gson gson;
    private final File secretsFile;
    private final Map<UUID, String> secretKeys;

    public TwoFactorManager(Path dataDirectory, Logger logger) {
        this.dataDirectory = dataDirectory;
        this.logger = logger;
        this.authenticator = new GoogleAuthenticator();
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.secretsFile = dataDirectory.resolve("2fa-secrets.json").toFile();
        this.secretKeys = new ConcurrentHashMap<>();
        
        // Create data directory if it doesn't exist
        try {
            if (!dataDirectory.toFile().exists()) {
                dataDirectory.toFile().mkdirs();
            }
        } catch (Exception e) {
            logger.error("Failed to create data directory", e);
        }
        
        loadSecrets();
    }

    /**
     * Generate a new secret key for a player
     */
    public String generateSecretKey(UUID playerUuid) {
        GoogleAuthenticatorKey key = authenticator.createCredentials();
        String secretKey = key.getKey();
        
        secretKeys.put(playerUuid, secretKey);
        saveSecrets();
        
        logger.info("Generated new 2FA secret for player: {}", playerUuid);
        return secretKey;
    }

    /**
     * Check if a player has a secret key
     */
    public boolean hasSecretKey(UUID playerUuid) {
        return secretKeys.containsKey(playerUuid);
    }

    /**
     * Get a player's secret key
     */
    public String getSecretKey(UUID playerUuid) {
        return secretKeys.get(playerUuid);
    }

    /**
     * Verify a 2FA code for a player
     */
    public boolean verifyCode(UUID playerUuid, String code) {
        String secretKey = secretKeys.get(playerUuid);
        if (secretKey == null) {
            return false;
        }

        try {
            int codeInt = Integer.parseInt(code);
            boolean isValid = authenticator.authorize(secretKey, codeInt);
            
            if (isValid) {
                logger.info("2FA verification successful for player: {}", playerUuid);
            } else {
                logger.warn("2FA verification failed for player: {}", playerUuid);
            }
            
            return isValid;
        } catch (NumberFormatException e) {
            logger.warn("Invalid 2FA code format from player {}: {}", playerUuid, code);
            return false;
        }
    }

    /**
     * Remove a player's secret key
     */
    public boolean removeSecretKey(UUID playerUuid) {
        boolean removed = secretKeys.remove(playerUuid) != null;
        if (removed) {
            saveSecrets();
            logger.info("Removed 2FA secret for player: {}", playerUuid);
        }
        return removed;
    }

    /**
     * Generate QR code URL for setup
     */
    public String generateQRUrl(String username, String secretKey) {
        String issuer = "Velocity2FA";
        String account = username + "@YourServer";
        
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL(issuer, account, 
            authenticator.createCredentials(secretKey));
    }

    /**
     * Get all players with 2FA enabled
     */
    public Map<UUID, String> getAllSecrets() {
        return new HashMap<>(secretKeys);
    }

    /**
     * Load secrets from file
     */
    private void loadSecrets() {
        if (!secretsFile.exists()) {
            logger.info("2FA secrets file doesn't exist, creating new one");
            return;
        }

        try (FileReader reader = new FileReader(secretsFile)) {
            Type type = new TypeToken<Map<String, String>>(){}.getType();
            Map<String, String> loadedSecrets = gson.fromJson(reader, type);
            
            if (loadedSecrets != null) {
                secretKeys.clear();
                for (Map.Entry<String, String> entry : loadedSecrets.entrySet()) {
                    try {
                        UUID uuid = UUID.fromString(entry.getKey());
                        secretKeys.put(uuid, entry.getValue());
                    } catch (IllegalArgumentException e) {
                        logger.warn("Invalid UUID in secrets file: {}", entry.getKey());
                    }
                }
                logger.info("Loaded {} 2FA secrets from file", secretKeys.size());
            }
        } catch (IOException e) {
            logger.error("Failed to load 2FA secrets", e);
        }
    }

    /**
     * Save secrets to file
     */
    private void saveSecrets() {
        try (FileWriter writer = new FileWriter(secretsFile)) {
            Map<String, String> saveData = new HashMap<>();
            for (Map.Entry<UUID, String> entry : secretKeys.entrySet()) {
                saveData.put(entry.getKey().toString(), entry.getValue());
            }
            
            gson.toJson(saveData, writer);
            logger.debug("Saved {} 2FA secrets to file", secretKeys.size());
        } catch (IOException e) {
            logger.error("Failed to save 2FA secrets", e);
        }
    }

    /**
     * Get statistics about 2FA usage
     */
    public int getTotalEnabledUsers() {
        return secretKeys.size();
    }
}
