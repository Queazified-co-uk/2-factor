package com.queazified.velocity2fa;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

class VerifiedSessionCache {
    private final Map<UUID, Instant> map = new ConcurrentHashMap<>();
    private final Duration ttl;

    public VerifiedSessionCache(Duration ttl) {
        this.ttl = ttl;
    }

    public void markVerified(UUID uuid) {
        map.put(uuid, Instant.now());
    }

    public boolean isVerified(UUID uuid) {
        Instant t = map.get(uuid);
        if (t == null) return false;
        if (Instant.now().isAfter(t.plus(ttl))) {
            map.remove(uuid);
            return false;
        }
        return true;
    }
}
