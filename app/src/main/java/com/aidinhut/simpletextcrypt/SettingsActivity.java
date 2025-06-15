package com.aidinhut.simpletextcrypt;

import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.EditText;
import androidx.appcompat.app.AppCompatActivity;

public class SettingsActivity extends AppCompatActivity {

    private EditText passcodeEditText;
    private EditText encryptionKeyEditText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        passcodeEditText = findViewById(R.id.passcodeEditText);
        encryptionKeyEditText = findViewById(R.id.encryptionKeyEditText);

        // Устанавливаем текстовый ввод для отображения паролей открытым текстом
        passcodeEditText.setInputType(InputType.TYPE_CLASS_TEXT);
        encryptionKeyEditText.setInputType(InputType.TYPE_CLASS_TEXT);

        // Получаем пароли из Intent
        String lockscreenPassword = getIntent().getStringExtra("lockscreen_password");
        String encryptionKey = getIntent().getStringExtra("encryption_key");

        // Отображаем пароли, если они переданы
        if (lockscreenPassword != null) {
            passcodeEditText.setText(lockscreenPassword);
        }
        if (encryptionKey != null) {
            encryptionKeyEditText.setText(encryptionKey);
        }
    }

    public void onSaveButtonClicked(View view) {
        String newLockscreenPassword = passcodeEditText.getText().toString();
        String newEncryptionKey = encryptionKeyEditText.getText().toString();

        try {
            SettingsManager.getInstance(this).saveSettings(newLockscreenPassword, newEncryptionKey, this);
            finish();
        } catch (Exception e) {
            Utilities.showErrorMessage(getString(R.string.settings_save_error), this);
        }
    }
}
