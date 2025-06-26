package com.aidinhut.simpletextcrypt;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * Provides methods for encrypting and decrypting data.
 * Исправлены:
 * 1. IV генерируется как 16 "сырых" байт через SecureRandom.
 * 2. Base64-вывод без переносов строк (NO_WRAP).
 * 3. Явно указана кодировка UTF-8.
 * 4. Соль (salt) для PBKDF2 — те же сырые 16 байт IV (можно вынести отдельно, но для минимальных правок оставлено так же).
 */
public class Crypter {

    // Длина IV в байтах
    private static final int IV_LENGTH = 16;
    // Число итераций PBKDF2
    private static final int PBKDF2_ITERATIONS = 27000;
    // Размер ключа в битах
    private static final int KEY_LENGTH = 256;

    public static String encrypt(String password, String input)
            throws UnsupportedEncodingException, GeneralSecurityException {

        // 1) Генерим 16 «сырых» байт для IV
        byte[] ivBytes = new byte[IV_LENGTH];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // 2) Деривация ключа на основе «сырых» байт IV как соли
        SecretKey secretKey = deriveKey(password, ivBytes);

        // 3) Шифруем
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encrypted = cipher.doFinal(input.getBytes("UTF-8"));

        // 4) Составляем строку: Base64(IV) ∥ Base64(ciphertext), без переносов
        String ivB64      = Base64.encodeToString(ivBytes,      Base64.NO_WRAP);
        String cipherB64  = Base64.encodeToString(encrypted,    Base64.NO_WRAP);
        return ivB64 + cipherB64;
    }

    public static String decrypt(String password, String input)
            throws UnsupportedEncodingException, GeneralSecurityException {
        // 1) Извлекаем Base64(IV) — известно, что это 24 символа (16 байт → 24 Base64-знака без «=»)
        String ivB64 = input.substring(0, 24);
        String cipherB64 = input.substring(24);

        byte[] ivBytes      = Base64.decode(ivB64,     Base64.NO_WRAP);
        byte[] encrypted    = Base64.decode(cipherB64, Base64.NO_WRAP);
        IvParameterSpec iv  = new IvParameterSpec(ivBytes);

        // 2) Деривация ключа
        SecretKey secretKey = deriveKey(password, ivBytes);

        // 3) Расшифровка
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] original = cipher.doFinal(encrypted);
        return new String(original, "UTF-8");
    }

    /**
     * Дериватит ключ из пароля и saltBytes (16 «сырых» байт IV).
     */
    private static SecretKey deriveKey(String password, byte[] saltBytes)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        char[] passwordChars = password.toCharArray();
        KeySpec spec = new PBEKeySpec(passwordChars, saltBytes, PBKDF2_ITERATIONS, KEY_LENGTH);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
}
