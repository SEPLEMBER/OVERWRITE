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
        loadPreviousSettings();
    }

    public void onSaveClicked(View view) {
        EditText encryptionKeyTextBox = findViewById(R.id.encryptionKeyEditText);
        EditText lockscreenPasswordTextBox = findViewById(R.id.passcodeEditText);
        EditText lockTimeoutTextBox = findViewById(R.id.lockTimeoutEdit);

        String encryptionKey = encryptionKeyTextBox.getText().toString();
        String lockscreenPassword = lockscreenPasswordTextBox.getText().toString();

        if (encryptionKey.length() < 8) {
            Utilities.showErrorMessage(getString(R.string.invalid_key_length_error), this);
            return;
        }
        if (lockscreenPassword.length() < 8) {
            Utilities.showErrorMessage(getString(R.string.invalid_lockscreen_password_error), this);
            return;
        }

        try {
            SettingsManager.getInstance(this).setLockscreenPassword(lockscreenPassword, this);
            SettingsManager.getInstance(this).setEncryptionKey(encryptionKey, lockscreenPassword, this);
            SettingsManager.getInstance(this).setLockTimeout(lockTimeoutTextBox.getText().toString(), this);
        } catch (Exception error) {
            Utilities.showErrorMessage(error.getMessage(), this);
            return;
        }

        finish();
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
        EditText lockscreenPasswordTextBox = findViewById(R.id.passcodeEditText);
        EditText lockTimeoutTextBox = findViewById(R.id.lockTimeoutEdit);

        try {
            lockscreenPasswordTextBox.setText(""); // Пароль не отображаем
            encryptionKeyTextBox.setText(""); // Ключ не отображаем
            lockTimeoutTextBox.setText(Integer.toString(SettingsManager.getInstance(this).getLockTimeout(this)));
        } catch (Exception error) {
            Utilities.showErrorMessage(error.getMessage(), this);
        }
    }
}
