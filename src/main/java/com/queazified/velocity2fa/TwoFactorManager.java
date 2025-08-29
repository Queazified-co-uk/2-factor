package com.queazified.velocity2fa;
import java.io.File;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;

public class TwoFactorManager {
    public java.util.Set<UUID> getAllSecretUUIDs() {
        return secretKeys.keySet();
    }
    private final Path storagePath;
    private final Logger logger;
    private final Map<UUID, String> secretKeys = new HashMap<>();
    private final File secretsFile;
    private final com.warrenstrange.googleauth.GoogleAuthenticator authenticator = new com.warrenstrange.googleauth.GoogleAuthenticator();

    public TwoFactorManager(Path storagePath, Logger logger) {
        this.storagePath = storagePath;
        this.logger = logger;
        this.secretsFile = storagePath.resolve("secrets.json").toFile();
        loadSecrets();
    }

    public boolean hasSecretKey(UUID uuid) {
        return secretKeys.containsKey(uuid);
    }

    public void removeSecretKey(UUID uuid) {
        secretKeys.remove(uuid);
        saveSecrets();
    }

    public boolean verifyCode(UUID uuid, String code) {
        String secret = secretKeys.get(uuid);
        if (secret == null) return false;
        try {
            int codeInt = Integer.parseInt(code);
            return authenticator.authorize(secret, codeInt);
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public String generateSecretKey(UUID uuid) {
        com.warrenstrange.googleauth.GoogleAuthenticatorKey key = authenticator.createCredentials();
        String secret = key.getKey();
        secretKeys.put(uuid, secret);
        saveSecrets();
        return secret;
    }

    public String generateQRUrl(String username, String secret) {
        // otpauth URL for authenticator apps
        String issuer = "Velocity2FA";
        return "otpauth://totp/" + issuer + ":" + username + "?secret=" + secret + "&issuer=" + issuer;
    }

    public int getTotalEnabledUsers() {
        return secretKeys.size();
    }

    private void loadSecrets() {
        if (!secretsFile.exists()) return;
        try (java.io.FileReader reader = new java.io.FileReader(secretsFile)) {
            com.google.gson.reflect.TypeToken<Map<String, String>> typeToken = new com.google.gson.reflect.TypeToken<>() {};
            Map<String, String> map = new com.google.gson.Gson().fromJson(reader, typeToken.getType());
            if (map != null) {
                secretKeys.clear();
                for (Map.Entry<String, String> entry : map.entrySet()) {
                    secretKeys.put(UUID.fromString(entry.getKey()), entry.getValue());
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to load secrets.json: {}", e.getMessage());
        }
    }

    private void saveSecrets() {
        try (java.io.FileWriter writer = new java.io.FileWriter(secretsFile)) {
            Map<String, String> map = new HashMap<>();
            for (Map.Entry<UUID, String> entry : secretKeys.entrySet()) {
                map.put(entry.getKey().toString(), entry.getValue());
            }
            new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(map, writer);
        } catch (Exception e) {
            logger.warn("Failed to save secrets.json: {}", e.getMessage());
        }
    }
}
