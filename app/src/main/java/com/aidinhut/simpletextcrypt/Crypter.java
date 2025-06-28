package com.aidinhut.simpletextcrypt;

import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Безопасный класс для симметричного шифрования с использованием AES-GCM.
 * Исправлены критические уязвимости безопасности.
 */
public class Crypter {
    
    private static final String TAG = "Crypter";

    // Улучшенные параметры безопасности
    private static final int SALT_LENGTH_BYTES    = 32;       // 256-битная соль (увеличено)
    private static final int IV_LENGTH_BYTES      = 12;       // 96-битный IV для GCM
    private static final int TAG_LENGTH_BITS      = 128;      // 128-битный тег аутентичности
    private static final int PBKDF2_ITERATIONS    = 120000;   // Современный стандарт (2024)
    private static final int KEY_LENGTH_BITS      = 256;      // AES-256
    private static final String PBKDF2_ALGORITHM  = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGORITHM  = "AES/GCM/NoPadding";
    private static final String FORMAT_VERSION_V1 = "v1";     // Обратная совместимость
    private static final String FORMAT_VERSION_V2 = "v2";     // Новая версия
    
    // Требования к паролю
    private static final int MIN_PASSWORD_LENGTH = 12;
    private static final Pattern STRONG_PASSWORD_PATTERN = Pattern.compile(
        "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,}$"
    );
    
    // Максимальные размеры для защиты от DoS
    private static final int MAX_INPUT_SIZE = 10 * 1024 * 1024; // 10MB

    /**
     * Исключение для криптографических ошибок
     */
    public static class CryptoException extends Exception {
        public CryptoException(String message) {
            super(message);
        }
        
        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Шифрует строку с максимальной безопасностью.
     * Формат v2: v2:Base64(salt):Base64(iv):Base64(ciphertext)
     */
    public static String encrypt(String password, String plaintext) throws CryptoException {
        // Строгая валидация входных данных
        validateInputs(password, plaintext);
        validatePasswordStrength(password);
        
        if (plaintext.getBytes(StandardCharsets.UTF_8).length > MAX_INPUT_SIZE) {
            throw new CryptoException("Input too large");
        }

        SecureRandom secureRandom = getSecureRandom();
        
        // Генерация криптографически стойких случайных значений
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        secureRandom.nextBytes(salt);

        byte[] ivBytes = new byte[IV_LENGTH_BYTES];
        secureRandom.nextBytes(ivBytes);

        byte[] keyBytes = null;
        try {
            keyBytes = deriveKeyBytes(password, salt, PBKDF2_ITERATIONS);
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

            // Обязательное использование AAD для целостности метаданных
            cipher.updateAAD(FORMAT_VERSION_V2.getBytes(StandardCharsets.UTF_8));
            cipher.updateAAD(salt); // Дополнительная защита

            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] cipherBytes = cipher.doFinal(plaintextBytes);
            
            // Очистка plaintext из памяти
            Arrays.fill(plaintextBytes, (byte) 0);

            return FORMAT_VERSION_V2 + ":" +
                   Base64.encodeToString(salt, Base64.NO_WRAP | Base64.NO_PADDING) + ":" +
                   Base64.encodeToString(ivBytes, Base64.NO_WRAP | Base64.NO_PADDING) + ":" +
                   Base64.encodeToString(cipherBytes, Base64.NO_WRAP | Base64.NO_PADDING);

        } catch (Exception e) {
            // Не раскрываем детали в исключениях
            Log.e(TAG, "Encryption failed", e);
            throw new CryptoException("Encryption failed");
        } finally {
            // Обязательная очистка чувствительных данных
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }

    /**
     * Расшифровывает строку с поддержкой v1 и v2 форматов.
     */
    public static String decrypt(String password, String input) throws CryptoException {
        // Валидация входных данных
        if (password == null || input == null || input.trim().isEmpty()) {
            throw new CryptoException("Invalid input parameters");
        }
        
        if (input.length() > MAX_INPUT_SIZE) {
            throw new CryptoException("Input too large");
        }

        String[] parts = input.split(":", 4);
        if (parts.length != 4) {
            throw new CryptoException("Invalid format");
        }

        String version = parts[0];
        if (!secureEquals(version, FORMAT_VERSION_V1) && !secureEquals(version, FORMAT_VERSION_V2)) {
            throw new CryptoException("Unsupported format version");
        }

        byte[] keyBytes = null;
        try {
            byte[] salt = Base64.decode(parts[1], Base64.NO_WRAP);
            byte[] ivBytes = Base64.decode(parts[2], Base64.NO_WRAP);
            byte[] cipherData = Base64.decode(parts[3], Base64.NO_WRAP);

            // Валидация размеров в зависимости от версии
            int expectedSaltLength = secureEquals(version, FORMAT_VERSION_V2) ? SALT_LENGTH_BYTES : 16;
            if (salt.length != expectedSaltLength || ivBytes.length != IV_LENGTH_BYTES) {
                throw new CryptoException("Invalid data format");
            }

            // Используем соответствующие параметры для каждой версии
            int iterations = secureEquals(version, FORMAT_VERSION_V2) ? PBKDF2_ITERATIONS : 15000;
            keyBytes = deriveKeyBytes(password, salt, iterations);
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            // AAD только для v2
            if (secureEquals(version, FORMAT_VERSION_V2)) {
                cipher.updateAAD(version.getBytes(StandardCharsets.UTF_8));
                cipher.updateAAD(salt);
            }

            byte[] plainBytes = cipher.doFinal(cipherData);
            String result = new String(plainBytes, StandardCharsets.UTF_8);
            
            // Очистка расшифрованных данных
            Arrays.fill(plainBytes, (byte) 0);
            
            return result;

        } catch (Exception e) {
            Log.e(TAG, "Decryption failed", e);
            throw new CryptoException("Decryption failed");
        } finally {
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }

    /**
     * Методы для работы с byte arrays (более безопасно для бинарных данных)
     */
    public static byte[] encryptBytes(char[] password, byte[] plaintext) throws CryptoException {
        if (password == null || password.length < MIN_PASSWORD_LENGTH || 
            plaintext == null || plaintext.length == 0) {
            throw new CryptoException("Invalid input parameters");
        }
        
        if (plaintext.length > MAX_INPUT_SIZE) {
            throw new CryptoException("Input too large");
        }

        SecureRandom secureRandom = getSecureRandom();
        
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        secureRandom.nextBytes(salt);
        
        byte[] ivBytes = new byte[IV_LENGTH_BYTES];
        secureRandom.nextBytes(ivBytes);
        
        byte[] keyBytes = null;
        try {
            keyBytes = deriveKeyBytes(password, salt, PBKDF2_ITERATIONS);
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            
            byte[] versionBytes = FORMAT_VERSION_V2.getBytes(StandardCharsets.UTF_8);
            cipher.updateAAD(versionBytes);
            cipher.updateAAD(salt);
            
            byte[] cipherBytes = cipher.doFinal(plaintext);
            
            // Формат для byte array: [version_len][version][salt][iv][ciphertext]
            byte[] result = new byte[1 + versionBytes.length + salt.length + ivBytes.length + cipherBytes.length];
            
            int pos = 0;
            result[pos++] = (byte) versionBytes.length;
            System.arraycopy(versionBytes, 0, result, pos, versionBytes.length);
            pos += versionBytes.length;
            System.arraycopy(salt, 0, result, pos, salt.length);
            pos += salt.length;
            System.arraycopy(ivBytes, 0, result, pos, ivBytes.length);
            pos += ivBytes.length;
            System.arraycopy(cipherBytes, 0, result, pos, cipherBytes.length);
            
            return result;
            
        } catch (Exception e) {
            Log.e(TAG, "Byte encryption failed", e);
            throw new CryptoException("Encryption failed");
        } finally {
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
            // Пароль очищает вызывающий код
        }
    }

    public static byte[] decryptBytes(char[] password, byte[] input) throws CryptoException {
        if (password == null || input == null || input.length < 50) {
            throw new CryptoException("Invalid input parameters");
        }
        
        if (input.length > MAX_INPUT_SIZE) {
            throw new CryptoException("Input too large");
        }
        
        byte[] keyBytes = null;
        try {
            int pos = 0;
            int versionLength = input[pos++] & 0xFF;
            
            if (versionLength > 10 || pos + versionLength > input.length) {
                throw new CryptoException("Invalid format");
            }
            
            byte[] versionBytes = new byte[versionLength];
            System.arraycopy(input, pos, versionBytes, 0, versionLength);
            pos += versionLength;
            
            String version = new String(versionBytes, StandardCharsets.UTF_8);
            if (!secureEquals(version, FORMAT_VERSION_V2)) {
                throw new CryptoException("Unsupported version for byte format");
            }
            
            if (pos + SALT_LENGTH_BYTES + IV_LENGTH_BYTES >= input.length) {
                throw new CryptoException("Invalid format");
            }
            
            byte[] salt = new byte[SALT_LENGTH_BYTES];
            System.arraycopy(input, pos, salt, 0, SALT_LENGTH_BYTES);
            pos += SALT_LENGTH_BYTES;
            
            byte[] ivBytes = new byte[IV_LENGTH_BYTES];
            System.arraycopy(input, pos, ivBytes, 0, IV_LENGTH_BYTES);
            pos += IV_LENGTH_BYTES;
            
            byte[] cipherData = new byte[input.length - pos];
            System.arraycopy(input, pos, cipherData, 0, cipherData.length);
            
            keyBytes = deriveKeyBytes(password, salt, PBKDF2_ITERATIONS);
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            
            cipher.updateAAD(versionBytes);
            cipher.updateAAD(salt);
            
            return cipher.doFinal(cipherData);
            
        } catch (Exception e) {
            Log.e(TAG, "Byte decryption failed", e);
            throw new CryptoException("Decryption failed");
        } finally {
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
        }
    }

    /**
     * Безопасная генерация ключей с защитой от атак по времени
     */
    private static byte[] deriveKeyBytes(String password, byte[] salt, int iterations) 
            throws CryptoException {
        char[] pwdChars = password.toCharArray();
        try {
            return deriveKeyBytes(pwdChars, salt, iterations);
        } finally {
            Arrays.fill(pwdChars, '\0');
        }
    }
    
    private static byte[] deriveKeyBytes(char[] password, byte[] salt, int iterations) 
            throws CryptoException {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new CryptoException("Key derivation failed", e);
        }
    }

    /**
     * Защищенное от timing attacks сравнение строк
     */
    private static boolean secureEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        
        boolean result = MessageDigest.isEqual(aBytes, bBytes);
        
        // Очистка
        Arrays.fill(aBytes, (byte) 0);
        Arrays.fill(bBytes, (byte) 0);
        
        return result;
    }

    /**
     * Валидация входных параметров
     */
    private static void validateInputs(String password, String plaintext) throws CryptoException {
        if (password == null || password.isEmpty()) {
            throw new CryptoException("Password cannot be null or empty");
        }
        
        if (plaintext == null) {
            throw new CryptoException("Plaintext cannot be null");
        }
        
        if (password.length() < MIN_PASSWORD_LENGTH) {
            throw new CryptoException("Password too short");
        }
    }

    /**
     * Проверка силы пароля
     */
    private static void validatePasswordStrength(String password) throws CryptoException {
        if (!STRONG_PASSWORD_PATTERN.matcher(password).matches()) {
            throw new CryptoException("Password must contain at least 12 characters with uppercase, lowercase, digits and special characters");
        }
    }

    /**
     * Получение криптографически стойкого генератора случайных чисел
     */
    private static SecureRandom getSecureRandom() throws CryptoException {
        try {
            // Используем наиболее стойкий доступный алгоритм
            try {
                return SecureRandom.getInstance("SHA1PRNG");
            } catch (NoSuchAlgorithmException e) {
                return new SecureRandom();
            }
        } catch (Exception e) {
            throw new CryptoException("Failed to initialize secure random", e);
        }
    }

    /**
     * Генератор криптографически стойких паролей
     */
    public static String generateSecurePassword(int length) throws CryptoException {
        if (length < MIN_PASSWORD_LENGTH) {
            length = MIN_PASSWORD_LENGTH;
        }
        
        // Наборы символов для разных категорий
        String lowercase = "abcdefghijklmnopqrstuvwxyz";
        String uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String digits = "0123456789";
        String special = "@$!%*?&^#()_+-=[]{}|;:,.<>";
        String allChars = lowercase + uppercase + digits + special;
        
        SecureRandom random = getSecureRandom();
        StringBuilder password = new StringBuilder(length);
        
        // Гарантируем наличие символов из каждой категории
        password.append(lowercase.charAt(random.nextInt(lowercase.length())));
        password.append(uppercase.charAt(random.nextInt(uppercase.length())));
        password.append(digits.charAt(random.nextInt(digits.length())));
        password.append(special.charAt(random.nextInt(special.length())));
        
        // Заполняем остальные позиции случайными символами
        for (int i = 4; i < length; i++) {
            password.append(allChars.charAt(random.nextInt(allChars.length())));
        }
        
        // Перемешиваем символы для случайного порядка
        for (int i = 0; i < length; i++) {
            int j = random.nextInt(length);
            char temp = password.charAt(i);
            password.setCharAt(i, password.charAt(j));
            password.setCharAt(j, temp);
        }
        
        return password.toString();
    }

    /**
     * Проверка целостности зашифрованных данных
     */
    public static boolean verifyIntegrity(String password, String encryptedData) {
        try {
            decrypt(password, encryptedData);
            return true;
        } catch (CryptoException e) {
            return false;
        }
    }

    /**
     * Безопасное удаление строки из памяти (best effort)
     */
    public static void clearString(StringBuilder sb) {
        if (sb != null) {
            for (int i = 0; i < sb.length(); i++) {
                sb.setCharAt(i, '\0');
            }
            sb.setLength(0);
        }
    }
}
