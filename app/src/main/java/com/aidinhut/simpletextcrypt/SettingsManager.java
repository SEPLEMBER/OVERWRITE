package com.aidinhut.simpletextcrypt;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class SettingsManager {
    private static SettingsManager instance;
    private SharedPreferences preferences;

    private SettingsManager(Context context) {
        preferences = context.getSharedPreferences(Constants.PREFERENCES_KEY, Context.MODE_PRIVATE);
        initializeDefaultEncryptionKey(context);
    }

    public static SettingsManager getInstance(Context context) {
        if (instance == null) {
            instance = new SettingsManager(context);
        }
        return instance;
    }

    public void setLockscreenPassword(String password, Context context) throws Exception {
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException(context.getString(R.string.invalid_lockscreen_password_error));
        }
        byte[] salt = generateSalt();
        String saltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP);
        String hash = computeHash(password, salt);
        preferences.edit()
            .putString("lockscreen_salt", saltBase64)
            .putString("lockscreen_hash", hash)
            .apply();
    }

    public boolean verifyLockscreenPassword(String password) throws Exception {
        String storedSaltBase64 = preferences.getString("lockscreen_salt", null);
        String storedHash = preferences.getString("lockscreen_hash", null);
        if (storedSaltBase64 == null || storedHash == null) {
            return password.equals(Constants.DEFAULT_LOCKSCREEN_PASSWORD);
        }
        byte[] salt = Base64.decode(storedSaltBase64, Base64.DEFAULT);
        String computedHash = computeHash(password, salt);
        return computedHash.equals(storedHash);
    }

    public boolean hasCustomLockscreenPassword() {
        return preferences.contains("lockscreen_salt") && preferences.contains("lockscreen_hash");
    }

    public void setEncryptionKey(String encryptionKey, String lockscreenPassword, Context context) throws Exception {
        if (encryptionKey == null || encryptionKey.length() < 8) {
            throw new IllegalArgumentException(context.getString(R.string.invalid_key_length_error));
        }
        if (!verifyLockscreenPassword(lockscreenPassword)) {
            throw new SecurityException(context.getString(R.string.wrong_lockscreen_password_error));
        }
        byte[] encryptionSalt = generateSalt();
        String encryptionSaltBase64 = Base64.encodeToString(encryptionSalt, Base64.NO_WRAP);
        byte[] iv = generateNonce();
        String ivBase64 = Base64.encodeToString(iv, Base64.NO_WRAP);
        SecretKey secretKey = deriveKey(lockscreenPassword, encryptionSalt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] encrypted = cipher.doFinal(encryptionKey.getBytes(StandardCharsets.UTF_8));
        String encryptedBase64 = Base64.encodeToString(encrypted, Base64.NO_WRAP);
        preferences.edit()
            .putString("encryption_salt", encryptionSaltBase64)
            .putString("encryption_iv", ivBase64)
            .putString("encrypted_encryption_key", encryptedBase64)
            .apply();
    }

    public String getDecryptedEncryptionKey(String lockscreenPassword, Context context) throws Exception {
        if (!verifyLockscreenPassword(lockscreenPassword)) {
            throw new SecurityException(context.getString(R.string.wrong_lockscreen_password_error));
        }
        String encryptionSaltBase64 = preferences.getString("encryption_salt", null);
        String ivBase64 = preferences.getString("encryption_iv", null);
        String encryptedBase64 = preferences.getString("encrypted_encryption_key", null);
        if (encryptionSaltBase64 == null || ivBase64 == null || encryptedBase64 == null) {
            initializeDefaultEncryptionKey(context);
            encryptionSaltBase64 = preferences.getString("encryption_salt", null);
            ivBase64 = preferences.getString("encryption_iv", null);
            encryptedBase64 = preferences.getString("encrypted_encryption_key", null);
        }
        byte[] encryptionSalt = Base64.decode(encryptionSaltBase64, Base64.DEFAULT);
        byte[] iv = Base64.decode(ivBase64, Base64.DEFAULT);
        byte[] encrypted = Base64.decode(encryptedBase64, Base64.DEFAULT);
        SecretKey secretKey = deriveKey(lockscreenPassword, encryptionSalt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public int getLockTimeout(Context context) {
        return preferences.getInt(Constants.LOCK_TIMEOUT_SETTINGS_KEY, 5);
    }

    public void setLockTimeout(String timeout, Context context) {
        try {
            int timeoutInt = Integer.parseInt(timeout);
            preferences.edit().putInt(Constants.LOCK_TIMEOUT_SETTINGS_KEY, timeoutInt).apply();
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid lock timeout value");
        }
    }

    private void initializeDefaultEncryptionKey(Context context) {
        if (preferences.getString("encrypted_encryption_key", null) == null) {
            try {
                setEncryptionKey(Constants.DEFAULT_ENCRYPTION_KEY, Constants.DEFAULT_LOCKSCREEN_PASSWORD, context);
            } catch (Exception e) {
                android.util.Log.e("SettingsManager", "Failed to set default encryption key", e);
            }
        }
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private byte[] generateNonce() {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private String computeHash(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 45000, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return Base64.encodeToString(hash, Base64.NO_WRAP);
    }

    private SecretKey deriveKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 35000, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }
}
