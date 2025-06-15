package com.aidinhut.simpletextcrypt;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import androidx.appcompat.app.AppCompatActivity;

public class LockActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_lock);
    }

    public void onUnlockButtonClicked(View view) {
        EditText passcodeEditText = findViewById(R.id.passcodeEditText);
        String passcode = passcodeEditText.getText().toString();

        try {
            if (SettingsManager.getInstance(this).verifyLockscreenPassword(passcode)) {
                // Проверяем ключ шифрования (он должен быть установлен по умолчанию)
                SettingsManager.getInstance(this).getDecryptedEncryptionKey(passcode, this);
                startActivity(new Intent(this, MainActivity.class));
                finish();
            } else {
                Utilities.showErrorMessage(getString(R.string.wrong_lockscreen_password_error), this);
            }
        } catch (Exception error) {
            Utilities.showErrorMessage(error.getMessage(), this);
        }
    }
}
