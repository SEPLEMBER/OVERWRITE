/*
 * This file is part of SimpleTextCrypt.
 * Copyright (c) 2015-2020, Aidin Gharibnavaz <aidin@aidinhut.com>
 *
 * SimpleTextCrypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SimpleTextCrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SimpleTextCrypt.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.aidinhut.simpletextcrypt;

import android.app.AlertDialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
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
        // Apply theme before setContentView
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
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

        // Language Spinner (English only for now)
        Spinner languageSpinner = findViewById(R.id.languageSpinner);
        ArrayAdapter<CharSequence> languageAdapter = ArrayAdapter.createFromResource(
                this, R.array.language_options, android.R.layout.simple_spinner_item);
        languageAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        languageSpinner.setAdapter(languageAdapter);

        String language = prefs.getString(PREF_LANGUAGE, "en");
        languageSpinner.setSelection("en".equals(language) ? 0 : 0); // Only English for now

        languageSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                selectedLanguage = "en"; // Only English for now
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
        EditText encryptionKeyTextBox = (EditText)findViewById(R.id.encryptionKeyEditText);
        EditText passcodeTextBox = (EditText)findViewById(R.id.passcodeEditText);
        EditText lockTimeoutTextBox = (EditText)findViewById(R.id.lockTimeoutEditText);

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
            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_SYSTEM);
            prefs.edit().putString(PREF_THEME, selectedTheme).apply();
            prefs.edit().putString(PREF_LANGUAGE, selectedLanguage).apply();
            setLocale(selectedLanguage);
        } catch (Exception error) {
            Utilities.showErrorMessage(error.getMessage(), this);
            return;
        }

        // Close the app
        finishAffinity();
    }

    public void onKeyCleanClicked(View view) {
        EditText encryptionKeyTextBox = (EditText)findViewById(R.id.encryptionKeyEditText);
        encryptionKeyTextBox.setText("");
    }

    @Override
    protected void onPause() {
        finish();
        super.onPause();
    }

    private void loadPreviousSettings() {
        EditText encryptionKeyTextBox = (EditText)findViewById(R.id.encryptionKeyEditText);
        EditText passcodeTextBox = (EditText)findViewById(R.id.passcodeEditText);
        EditText lockTimeoutTextBox = (EditText)findViewById(R.id.lockTimeoutEditText);

        try {
            encryptionKeyTextBox.setText(SettingsManager.getInstance().getEncryptionKey(this));
            passcodeTextBox.setText(SettingsManager.getInstance().getPasscode(this));
            lockTimeoutTextBox.setText(Integer.toString(SettingsManager.getInstance().getLockTimeout(this)));
            selectedTheme = getSharedPreferences(PREFS_NAME, MODE_PRIVATE).getString(PREF_THEME, "light");
            selectedLanguage = getSharedPreferences(PREFS_NAME, MODE_PRIVATE).getString(PREF_LANGUAGE, "en");
        } catch (Exception error) {
            Utilities.showErrorMessage(error.getMessage(), this);
        }
    }
}
