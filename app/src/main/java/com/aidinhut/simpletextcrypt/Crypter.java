package com.aidinhut.simpletextcrypt;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import java.security.GeneralSecurityException;

public class SettingsManager {
    
    private static final String TAG = "SettingsManager";
    private static final String PREFS_NAME = "SimpleTextCryptPrefs";
    private static final String KEY_ENCRYPTED_PASSCODE = "encrypted_passcode";
    private static final String KEY_ENCRYPTED_DATA = "encrypted_data_";
    
    private final SharedPreferences prefs;
    private String passcode;

    public SettingsManager(Context context) {
        this.prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    /**
     * Устанавливает пасскод для шифрования
     */
    public boolean setPasscode(String passcode) {
        if (passcode == null || passcode.trim().isEmpty()) {
            Log.e(TAG, "Passcode cannot be null or empty");
            return false;
        }
        
        try {
            // Шифруем пасскод самим собой для проверки
            String encryptedPasscode = Crypter.encrypt(passcode, passcode);
            
            prefs.edit()
                .putString(KEY_ENCRYPTED_PASSCODE, encryptedPasscode)
                .apply();
            
            this.passcode = passcode;
            return true;
            
        } catch (Crypter.CryptoException e) {
            Log.e(TAG, "Failed to set passcode", e);
            return false;
        }
    }

    /**
     * Проверяет правильность пасскода
     */
    public boolean verifyPasscode(String inputPasscode) {
        if (inputPasscode == null || !hasPasscode()) {
            return false;
        }
        
        try {
            String storedEncryptedPasscode = prefs.getString(KEY_ENCRYPTED_PASSCODE, null);
            if (storedEncryptedPasscode == null) {
                return false;
            }
            
            String decryptedPasscode = Crypter.decrypt(inputPasscode, storedEncryptedPasscode);
            
            // Безопасное сравнение
            boolean isValid = constantTimeEquals(inputPasscode, decryptedPasscode);
            
            if (isValid) {
                this.passcode = inputPasscode;
            }
            
            return isValid;
            
        } catch (Crypter.CryptoException e) {
            Log.e(TAG, "Failed to verify passcode", e);
            return false;
        }
    }

    /**
     * Проверяет, установлен ли пасскод
     */
    public boolean hasPasscode() {
        return prefs.contains(KEY_ENCRYPTED_PASSCODE);
    }

    /**
     * Сохраняет зашифрованные данные
     */
    public boolean saveEncryptedData(String key, String data) {
        if (!isUnlocked() || key == null || data == null) {
            Log.e(TAG, "Cannot save data: not unlocked or invalid parameters");
            return false;
        }
        
        try {
            String encryptedData = Crypter.encrypt(this.passcode, data);
            
            prefs.edit()
                .putString(KEY_ENCRYPTED_DATA + key, encryptedData)
                .apply();
            
            return true;
            
        } catch (Crypter.CryptoException e) {
            Log.e(TAG, "Failed to save encrypted data for key: " + key, e);
            return false;
        }
    }

    /**
     * Загружает и расшифровывает данные
     */
    public String loadDecryptedData(String key) {
        if (!isUnlocked() || key == null) {
            Log.e(TAG, "Cannot load data: not unlocked or invalid key");
            return null;
        }
        
        try {
            String encryptedData = prefs.getString(KEY_ENCRYPTED_DATA + key, null);
            if (encryptedData == null) {
                return null;
            }
            
            return Crypter.decrypt(this.passcode, encryptedData);
            
        } catch (Crypter.CryptoException e) {
            Log.e(TAG, "Failed to load encrypted data for key: " + key, e);
            return null;
        }
    }

    /**
     * Проверяет, разблокирован ли менеджер настроек
     */
    public boolean isUnlocked() {
        return this.passcode != null && !this.passcode.isEmpty();
    }

    /**
     * Блокирует доступ (очищает пасскод из памяти)
     */
    public void lock() {
        if (this.passcode != null) {
            // Безопасная очистка пасскода из памяти
            char[] chars = this.passcode.toCharArray();
            java.util.Arrays.fill(chars, '\0');
            this.passcode = null;
        }
    }

    /**
     * Удаляет все сохраненные данные
     */
    public boolean clearAllData() {
        try {
            prefs.edit().clear().apply();
            lock();
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to clear all data", e);
            return false;
        }
    }

    /**
     * Удаляет конкретный ключ
     */
    public boolean removeData(String key) {
        if (key == null) {
            return false;
        }
        
        try {
            prefs.edit()
                .remove(KEY_ENCRYPTED_DATA + key)
                .apply();
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to remove data for key: " + key, e);
            return false;
        }
    }

    /**
     * Получает список всех сохраненных ключей
     */
    public java.util.Set<String> getSavedKeys() {
        java.util.Set<String> allKeys = prefs.getAll().keySet();
        java.util.Set<String> dataKeys = new java.util.HashSet<>();
        
        String prefix = KEY_ENCRYPTED_DATA;
        for (String key : allKeys) {
            if (key.startsWith(prefix)) {
                dataKeys.add(key.substring(prefix.length()));
            }
        }
        
        return dataKeys;
    }

    /**
     * Проверяет существование ключа
     */
    public boolean hasKey(String key) {
        if (key == null) {
            return false;
        }
        return prefs.contains(KEY_ENCRYPTED_DATA + key);
    }

    /**
     * Изменяет пасскод (перешифровывает все данные)
     */
    public boolean changePasscode(String oldPasscode, String newPasscode) {
        if (!verifyPasscode(oldPasscode)) {
            Log.e(TAG, "Old passcode verification failed");
            return false;
        }
        
        if (newPasscode == null || newPasscode.trim().isEmpty()) {
            Log.e(TAG, "New passcode cannot be null or empty");
            return false;
        }
        
        try {
            // Получаем все сохраненные ключи
            java.util.Set<String> keys = getSavedKeys();
            java.util.Map<String, String> decryptedData = new java.util.HashMap<>();
            
            // Расшифровываем все данные старым паролем
            for (String key : keys) {
                String data = loadDecryptedData(key);
                if (data != null) {
                    decryptedData.put(key, data);
                }
            }
            
            // Устанавливаем новый пасскод
            if (!setPasscode(newPasscode)) {
                return false;
            }
            
            // Зашифровываем все данные новым паролем
            boolean allSuccess = true;
            for (java.util.Map.Entry<String, String> entry : decryptedData.entrySet()) {
                if (!saveEncryptedData(entry.getKey(), entry.getValue())) {
                    Log.e(TAG, "Failed to re-encrypt data for key: " + entry.getKey());
                    allSuccess = false;
                }
            }
            
            // Очищаем расшифрованные данные из памяти
            decryptedData.clear();
            
            return allSuccess;
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to change passcode", e);
            return false;
        }
    }

    /**
     * Экспортирует все данные в зашифрованном виде
     */
    public String exportData() {
        if (!isUnlocked()) {
            return null;
        }
        
        try {
            java.util.Map<String, ?> allPrefs = prefs.getAll();
            org.json.JSONObject jsonObject = new org.json.JSONObject();
            
            for (java.util.Map.Entry<String, ?> entry : allPrefs.entrySet()) {
                jsonObject.put(entry.getKey(), entry.getValue().toString());
            }
            
            return jsonObject.toString();
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to export data", e);
            return null;
        }
    }

    /**
     * Импортирует данные из строки JSON
     */
    public boolean importData(String jsonData) {
        if (!isUnlocked() || jsonData == null) {
            return false;
        }
        
        try {
            org.json.JSONObject jsonObject = new org.json.JSONObject(jsonData);
            SharedPreferences.Editor editor = prefs.edit();
            
            java.util.Iterator<String> keys = jsonObject.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                String value = jsonObject.getString(key);
                editor.putString(key, value);
            }
            
            editor.apply();
            return true;
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to import data", e);
            return false;
        }
    }

    /**
     * Безопасное сравнение строк (защита от timing attacks)
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        
        if (a.length() != b.length()) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        
        return result == 0;
    }

    /**
     * Проверяет целостность всех сохраненных данных
     */
    public boolean verifyDataIntegrity() {
        if (!isUnlocked()) {
            return false;
        }
        
        try {
            java.util.Set<String> keys = getSavedKeys();
            
            for (String key : keys) {
                String encryptedData = prefs.getString(KEY_ENCRYPTED_DATA + key, null);
                if (encryptedData != null && !Crypter.verifyIntegrity(this.passcode, encryptedData)) {
                    Log.w(TAG, "Data integrity check failed for key: " + key);
                    return false;
                }
            }
            
            return true;
            
        } catch (Exception e) {
            Log.e(TAG, "Failed to verify data integrity", e);
            return false;
        }
    }

    /**
     * Получает статистику использования
     */
    public java.util.Map<String, Object> getStats() {
        java.util.Map<String, Object> stats = new java.util.HashMap<>();
        
        stats.put("hasPasscode", hasPasscode());
        stats.put("isUnlocked", isUnlocked());
        stats.put("totalKeys", getSavedKeys().size());
        stats.put("dataIntegrityOk", isUnlocked() ? verifyDataIntegrity() : false);
        
        return stats;
    }
}
