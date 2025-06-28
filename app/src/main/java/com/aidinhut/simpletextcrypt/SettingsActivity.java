/*
 * This file is part of ZER0LESS.
 * Copyright (c) 2015-2020, Aidin Gharibnavaz <aidin@aidinhut.com>
 *
 * ZER0LESS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ZER0LESS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ZER0LESS.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.aidinhut.simpletextcrypt;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import android.view.WindowManager;
import java.util.Locale;

public class SettingsActivity extends AppCompatActivity {

    private static final String PREFS_NAME = "AppPrefs";
    private static final String PREF_THEME = "theme";
    private static final String PREF_LANGUAGE = "language";
    private String selectedTheme;
    private String selectedLanguage;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // Apply saved locale
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String language = prefs.getString(PREF_LANGUAGE, "ru");
        setLocale(language);

        // Apply theme before setContentView
        String theme = prefs.getString(PREF_THEME, "light");
        if (theme.equals("dark")) {
            setTheme(R.style.AppTheme_Dark);
        } else if (theme.equals("amoled")) {
            setTheme(R.style.AppTheme_Amoled);
        } else {
            setTheme(R.style.AppTheme);
        }

        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, 
                            WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_settings);

        // Set warning text
        TextView warningText = findViewById(R.id.themeLanguageWarning);
        warningText.setText(R.string.theme_language_warning);

        setupSpinners();
        loadPreviousSettings();
    }

    private void setupSpinners() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        
        // Theme Spinner
        Spinner themeSpinner = findViewById(R.id.themeSpinner);
        ArrayAdapter<CharSequence> themeAdapter = ArrayAdapter.createFromResource(
                this, R.array.theme_options, android.R.layout.simple_spinner_item);
        themeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        themeSpinner.setAdapter(themeAdapter);

        String theme = prefs.getString(PREF_THEME, "light");
        if (theme.equals("dark")) {
            themeSpinner.setSelection(1);
        } else if (theme.equals("amoled")) {
            themeSpinner.setSelection(2);
        } else {
            themeSpinner.setSelection(0);
        }

        themeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (position == 0) {
                    selectedTheme = "light";
                } else if (position == 1) {
                    selectedTheme = "dark";
                } else {
                    selectedTheme = "amoled";
                }
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        // Language Spinner
        Spinner languageSpinner = findViewById(R.id.languageSpinner);
        ArrayAdapter<CharSequence> languageAdapter = ArrayAdapter.createFromResource(
                this, R.array.language_options, android.R.layout.simple_spinner_item);
        languageAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        languageSpinner.setAdapter(languageAdapter);

        String language = prefs.getString(PREF_LANGUAGE, "ru");
        String[] languageCodes = {"ru", "uk", "ja", "es", "de", "it", "fr", "en"};
        for (int i = 0; i < languageCodes.length; i++) {
            if (language.equals(languageCodes[i])) {
                languageSpinner.setSelection(i);
                break;
            }
        }

        languageSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                String[] languageCodes = {"ru", "uk", "ja", "es", "de", "it", "fr", "en"};
                selectedLanguage = languageCodes[position];
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });
    }

    private void setLocale(String language) {
        Locale locale = new Locale(language);
        Locale.setDefault(locale);
        android.content.res.Configuration config = new android.content.res.Configuration();
        config.setLocale(locale);
        getResources().updateConfiguration(config, getResources().getDisplayMetrics());
    }

    public void onSaveClicked(View view) {
        EditText encryptionKeyTextBox = findViewById(R.id.encryptionKeyEditText);
        EditText passcodeTextBox = findViewById(R.id.passcodeEditText);
        EditText lockTimeoutTextBox = findViewById(R.id.lockTimeoutEditText);

        if (encryptionKeyTextBox.getText().toString().length() < 3) {
            Utilities.showErrorMessage(getString(R.string.invalid_key_error), this);
            return;
        }
        if (passcodeTextBox.getText().toString().length() < 2) {
            Utilities.showErrorMessage(getString(R.string.invalid_passcode_error), this);
            return;
        }

        // Saving settings
        try {
            SettingsManager.getInstance().setPasscode(passcodeTextBox.getText().toString(), this);
            SettingsManager.getInstance().setEncryptionKey(encryptionKeyTextBox.getText().toString(), this);
            SettingsManager.getInstance().setLockTimeout(lockTimeoutTextBox.getText().toString(), this);
            
            // Save theme and language
            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
            prefs.edit().putString(PREF_THEME, selectedTheme).apply();
            prefs.edit().putString(PREF_LANGUAGE, selectedLanguage).apply();
            
            // Apply new locale
            setLocale(selectedLanguage);
            
            // Restart the app
            Intent intent = new Intent(this, MainActivity.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            finishAffinity();
            startActivity(intent);
        } catch (Exception error) {
            Utilities.showErrorMessage(error.getMessage(), this);
            return;
        }
    }

    public void onKeyCleanClicked(View view) {
        EditText encryptionKeyTextBox = findViewById(R.id.encryptionKeyEditText);
        encryptionKeyTextBox.setText("");
    }

    @Override
    protected void onPause() {
        finish();
        super.onPause();
    }

    private void loadPreviousSettings() {
        EditText encryptionKeyTextBox = findViewById(R.id.encryptionKeyEditText);
        EditText passcodeTextBox = findViewById(R.id.passcodeEditText);
        EditText lockTimeoutTextBox = findViewById(R.id.lockTimeoutEditText);

        try {
            encryptionKeyTextBox.setText(SettingsManager.getInstance().getEncryptionKey(this));
            passcodeTextBox.setText(SettingsManager.getInstance().getPasscode(this));
            lockTimeoutTextBox.setText(Integer.toString(SettingsManager.getInstance().getLockTimeout(this)));
            selectedTheme = getSharedPreferences(PREFS_NAME, MODE_PRIVATE).getString(PREF_THEME, "light");
            selectedLanguage = getSharedPreferences(PREFS_NAME, MODE_PRIVATE).getString(PREF_LANGUAGE, "ru");
        } catch (Exception error) {
            Utilities.showErrorMessage(error.getMessage(), this);
        }
    }
}
