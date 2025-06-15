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
            encryptionKey = "";
            lockscreenPassword = "";
            finish();
        } catch (Exception e) {
            encryptionKey = "";
            lockscreenPassword = "";
            Utilities.showErrorMessage(e.getMessage(), this);
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
        EditText lockscreenPasswordTextBox = findViewById(R.id.passcodeEditText);
        EditText lockTimeoutTextBox = findViewById(R.id.lockTimeoutEdit);
        String lockscreenPassword;

        try {
            // Получаем пароль экрана блокировки из Intent
            lockscreenPassword = getIntent().getStringExtra("lockscreen_password");
            if (lockscreenPassword == null) {
                // Если пароль не передан, используем дефолтный (для первой установки)
                lockscreenPassword = Constants.DEFAULT_LOCKSCREEN_PASSWORD;
                lockscreenPasswordTextBox.setHint(R.string.lockscreen_password_set_hint);
            }
            if (lockscreenPassword.equals(Constants.DEFAULT_LOCKSCREEN_PASSWORD)) {
                Utilities.showErrorMessage(getString(R.string.default_passcode_warning), this);
            }
            lockscreenPasswordTextBox.setText(lockscreenPassword);

            // Загружаем ключ шифрования, используя пароль из ОЗУ
            String currentKey = SettingsManager.getInstance(this).getDecryptedEncryptionKey(
                lockscreenPassword, this);
            encryptionKeyTextBox.setText(currentKey);

            // Загружаем таймаут блокировки
            int timeout = SettingsManager.getInstance(this).getLockTimeout(this);
            lockTimeoutTextBox.setText(Integer.toString(timeout));
        } catch (Exception e) {
            Utilities.showErrorMessage(e.getMessage(), this);
        } finally {
            lockscreenPassword = "";
        }
    }
}
