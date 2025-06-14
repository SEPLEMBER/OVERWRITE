package com.aidinhut.simpletextcrypt;

import android.content.Context;
import android.content.SharedPreferences;

import com.aidinhut.simpletextcrypt.exceptions.EncryptionKeyNotSet;
import com.aidinhut.simpletextcrypt.exceptions.SettingsNotSavedException;
import com.aidinhut.simpletextcrypt.exceptions.WrongPasscodeException;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class SettingsManager {

    private static SettingsManager instance;
    private char[] passcode = "1111".toCharArray();

    private SettingsManager() {
    }

    public static SettingsManager getInstance() {
        if (instance == null) {
            instance = new SettingsManager();
        }
        return instance;
    }

    public String tryGetPasscode(String passcode, Context context)
            throws UnsupportedEncodingException, GeneralSecurityException, WrongPasscodeException {
        SharedPreferences sharedPref = context.getSharedPreferences(Constants.PREFERENCES_KEY,
                Context.MODE_PRIVATE);

        if (!sharedPref.contains(Constants.PASSCODE_SETTINGS_KEY)) {
            return Constants.DEFAULT_PASSCODE;
        }

        this.passcode = passcode.toCharArray();

        try {
            String result = Crypter.decrypt(this.passcode,
                    sharedPref.getString(Constants.PASSCODE_SETTINGS_KEY, Constants.DEFAULT_PASSCODE));
            return result;
        } catch (IllegalBlockSizeException | BadPaddingException error) {
            Arrays.fill(this.passcode, '\0'); // Очистка пароля
            throw new WrongPasscodeException(context);
        }
    }

    public String getPasscode(Context context)
            throws UnsupportedEncodingException, GeneralSecurityException {
        SharedPreferences sharedPref = context.getSharedPreferences(Constants.PREFERENCES_KEY,
                Context.MODE_PRIVATE);

        if (!sharedPref.contains(Constants.PASSCODE_SETTINGS_KEY)) {
            return Constants.DEFAULT_PASSCODE;
        }

        return Crypter.decrypt(this.passcode,
                sharedPref.getString(Constants.PASSCODE_SETTINGS_KEY, Constants.DEFAULT_PASSCODE));
    }

    public void setPasscode(String passcode, Context context)
            throws UnsupportedEncodingException, GeneralSecurityException, SettingsNotSavedException {
        char[] newPasscode = passcode.toCharArray();

        SharedPreferences sharedPref = context.getSharedPreferences(Constants.PREFERENCES_KEY,
                Context.MODE_PRIVATE);
        SharedPreferences.Editor prefEditor = sharedPref.edit();

        prefEditor.putString(Constants.PASSCODE_SETTINGS_KEY,
                Crypter.encrypt(newPasscode, new String(newPasscode)));

        if (!prefEditor.commit()) {
            Arrays.fill(newPasscode, '\0');
            throw new SettingsNotSavedException(context);
        }

        Arrays.fill(this.passcode, '\0'); // Очистка старого пароля
        this.passcode = newPasscode;
    }

    public String getEncryptionKey(Context context)
            throws UnsupportedEncodingException, GeneralSecurityException, EncryptionKeyNotSet {
        SharedPreferences sharedPref = context.getSharedPreferences(Constants.PREFERENCES_KEY,
                Context.MODE_PRIVATE);

        if (!sharedPref.contains(Constants.ENCRYPTION_KEY_SETTINGS_KEY)) {
            return "";
        }

        return Crypter.decrypt(this.passcode,
                sharedPref.getString(Constants.ENCRYPTION_KEY_SETTINGS_KEY, ""));
    }

    public void setEncryptionKey(String key, Context context)
            throws UnsupportedEncodingException, GeneralSecurityException, SettingsNotSavedException {
        SharedPreferences sharedPref = context.getSharedPreferences(Constants.PREFERENCES_KEY,
                Context.MODE_PRIVATE);
        SharedPreferences.Editor prefEditor = sharedPref.edit();

        prefEditor.putString(Constants.ENCRYPTION_KEY_SETTINGS_KEY,
                Crypter.encrypt(this.passcode, key));

        if (!prefEditor.commit()) {
            throw new SettingsNotSavedException(context);
        }
    }

    public void setLockTimeout(String timeout, Context context) throws SettingsNotSavedException {
        SharedPreferences sharedPref = context.getSharedPreferences(Constants.PREFERENCES_KEY,
                Context.MODE_PRIVATE);
        SharedPreferences.Editor prefEditor = sharedPref.edit();

        int intTimeout = 0;
        if (timeout != null && !timeout.isEmpty()) {
            intTimeout = Integer.parseInt(timeout);
        }

        prefEditor.putInt(Constants.LOCK_TIMEOUT_SETTINGS_KEY, intTimeout);

        if (!prefEditor.commit()) {
            throw new SettingsNotSavedException(context);
        }
    }

    public int getLockTimeout(Context context) {
        SharedPreferences sharedPref = context.getSharedPreferences(Constants.PREFERENCES_KEY,
                Context.MODE_PRIVATE);

        if (!sharedPref.contains(Constants.LOCK_TIMEOUT_SETTINGS_KEY)) {
            return 0;
        }

        return sharedPref.getInt(Constants.LOCK_TIMEOUT_SETTINGS_KEY, 0);
    }

    // Очистка passcode при уничтожении объекта
    public void clearPasscode() {
        if (this.passcode != null) {
            Arrays.fill(this.passcode, '\0');
            this.passcode = null;
        }
    }
}
