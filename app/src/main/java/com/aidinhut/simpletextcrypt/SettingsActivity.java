package com.aidinhut.simpletextcrypt;

import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import androidx.appcompat.app.AppCompatActivity;

public class SettingsActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        // Инициализация полей ввода
        EditText lockTimeoutTextBox = findViewById(R.id.lockTimeoutEdit);
        lockTimeoutTextBox.setText(String.valueOf(SettingsManager.getInstance(this).getLockTimeout(this)));
    }

    public void onKeyCleanClicked(View view) {
        EditText encryptionKeyTextBox = findViewById(R.id.encryptionKeyEditText);
        encryptionKeyTextBox.setText("");
        EditText passcodeTextBox = findViewById(R.id.passcodeEditText);
        passcodeTextBox.setText("");
    }

    public void onSaveClicked(View view) {
        try {
            EditText encryptionKeyTextBox = findViewById(R.id.encryptionKeyEditText);
            String encryptionKey = encryptionKeyTextBox.getText().toString();
            EditText passcodeTextBox = findViewById(R.id.passcodeEditText);
            String lockscreenPassword = passcodeTextBox.getText().toString();
            EditText lockTimeoutTextBox = findViewById(R.id.lockTimeoutEdit);
            String lockTimeout = lockTimeoutTextBox.getText().toString();

            SettingsManager settingsManager = SettingsManager.getInstance(this);
            if (!lockscreenPassword.isEmpty()) {
                settingsManager.setLockscreenPassword(lockscreenPassword, this);
            }
            if (!encryptionKey.isEmpty()) {
                settingsManager.setEncryptionKey(encryptionKey, lockscreenPassword, this);
            }
            settingsManager.setLockTimeout(lockTimeout, this);

            Utilities.showMessage(getString(R.string.settings_saved), this);
            finish();
        } catch (Exception e) {
            Utilities.showErrorMessage(e.getMessage(), this);
        }
    }
}
