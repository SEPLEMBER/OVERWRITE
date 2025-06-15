package com.aidinhut.simpletextcrypt;

import android.content.Context;
import android.content.SharedPreferences;

public class SettingsManager {
    private static SettingsManager instance;
    private SharedPreferences preferences;

    private SettingsManager(Context context) {
        preferences = context.getSharedPreferences(Constants.PREFERENCES_KEY, Context.MODE_PRIVATE);
    }

    public static SettingsManager getInstance(Context context) {
        if (instance == null) {
            instance = new SettingsManager(context);
        }
        return instance;
    }

    public String getPasscode(Context context) {
        String passcode = preferences.getString(Constants.PASSCODE_SETTINGS_KEY, null);
        if (passcode == null) {
            return Constants.DEFAULT_PASSCODE;
        }
        return passcode;
    }

    public void setPasscode(String passcode, Context context) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(Constants.PASSCODE_SETTINGS_KEY, passcode);
        editor.apply();
    }

    public int getLockTimeout(Context context) {
        return preferences.getInt(Constants.LOCK_TIMEOUT_SETTINGS_KEY, 5);
    }

    public void setLockTimeout(String timeout, Context context) {
        try {
            int timeoutInt = Integer.parseInt(timeout);
            SharedPreferences.Editor editor = preferences.edit();
            editor.putInt(Constants.LOCK_TIMEOUT_SETTINGS_KEY, timeoutInt);
            editor.apply();
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid lock timeout value");
        }
    }

    public String getEncryptionKey(Context context) {
        return preferences.getString(Constants.ENCRYPTION_KEY_SETTINGS_KEY, "");
    }

    public void setEncryptionKey(String key, Context context) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(Constants.ENCRYPTION_KEY_SETTINGS_KEY, key);
        editor.apply();
    }
}
