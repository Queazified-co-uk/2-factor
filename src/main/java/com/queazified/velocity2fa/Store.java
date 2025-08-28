package com.queazified.velocity2fa;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

class Store {
    private final Path file;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private final Map<String, Entry> data = new HashMap<>();
    private final SecureRandom rng = new SecureRandom();

    static class Entry {
        String username;
        String secret; // base32
    }

    public Store(Path file) throws IOException {
        this.file = file;
        if (Files.exists(file)) {
            try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                Map<String, Entry> loaded = gson.fromJson(r, data.getClass());
                if (loaded != null) data.putAll(loaded);
            }
        }
    }

    public synchronized String getOrCreateSecret(UUID uuid, String username) {
        String key = uuid.toString();
        Entry e = data.get(key);
        if (e == null) {
            e = new Entry();
            e.username = username;
            e.secret = Base32.encode(randomBytes(20)); // 160-bit secret
            data.put(key, e);
            saveQuiet();
        } else {
            e.username = username;
        }
        return e.secret;
    }

    public synchronized Optional<String> getSecret(UUID uuid) {
        Entry e = data.get(uuid.toString());
        return e == null ? Optional.empty() : Optional.of(e.secret);
    }

    private byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        rng.nextBytes(b);
        return b;
    }

    private void saveQuiet() {
        try {
            if (!Files.exists(file.getParent())) Files.createDirectories(file.getParent());
            try (Writer w = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                gson.toJson(data, w);
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    // Minimal Base32 (RFC 4648) encoder
    static class Base32 {
        private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        public static String encode(byte[] bytes) {
            StringBuilder out = new StringBuilder((bytes.length * 8 + 4) / 5);
            int buffer = 0, bitsLeft = 0;
            for (byte aByte : bytes) {
                buffer = (buffer << 8) | (aByte & 0xFF);
                bitsLeft += 8;
                while (bitsLeft >= 5) {
                    int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                    bitsLeft -= 5;
                    out.append(ALPHABET.charAt(index));
                }
            }
            if (bitsLeft > 0) {
                int index = (buffer << (5 - bitsLeft)) & 0x1F;
                out.append(ALPHABET.charAt(index));
            }
            return out.toString();
        }
    }
}
