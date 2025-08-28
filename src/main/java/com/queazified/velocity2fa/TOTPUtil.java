package com.queazified.velocity2fa;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class TOTPUtil {

    public static String buildOtpAuthURL(String issuer, String account, String base32Secret) {
        String label = urlEncode(issuer) + ":" + urlEncode(account);
        String params = "secret=" + base32Secret + "&issuer=" + urlEncode(issuer) + "&algorithm=SHA1&digits=6&period=30";
        return "otpauth://totp/" + label + "?" + params;
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    public static boolean verifyCode(String base32Secret, String code, int window) {
        long timeStep = System.currentTimeMillis() / 1000L / 30L;
        code = code.trim();
        for (int i = -window; i <= window; i++) {
            String candidate = generateCode(base32Secret, timeStep + i);
            if (secureEquals(candidate, code)) return true;
        }
        return false;
    }

    public static String generateCode(String base32Secret, long timeStep) {
        byte[] key = base32Decode(base32Secret);
        byte[] data = ByteBuffer.allocate(8).putLong(timeStep).array();
        byte[] hash = hmacSha1(key, data);
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24) |
                     ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) |
                     (hash[offset + 3] & 0xFF);
        int otp = binary % 1_000_000;
        return String.format(Locale.ROOT, "%06d", otp);
    }

    private static byte[] hmacSha1(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Base32 decode (RFC 4648) without padding
    private static byte[] base32Decode(String s) {
        s = s.replace("=", "").toUpperCase(Locale.ROOT);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int buffer = 0, bitsLeft = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (char c : s.toCharArray()) {
            int val = alphabet.indexOf(c);
            if (val < 0) continue;
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return out.toByteArray();
    }
}
