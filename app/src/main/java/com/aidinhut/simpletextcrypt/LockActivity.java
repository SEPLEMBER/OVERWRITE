package com.aidinhut.simpletextcrypt;

import android.content.Intent;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class LockActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_lock);

        ((EditText)findViewById(R.id.passcodeEditText)).setOnEditorActionListener(
                new TextView.OnEditorActionListener() {
                    @Override
                    public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                        if (actionId == EditorInfo.IME_ACTION_DONE) {
                            unlock();
                            return true;
                        }
                        return false;
                    }
                }
        );
    }

    public void onUnlockButtonClicked(View view) {
        unlock();
    }

    private void unlock() {
        EditText passcodeBox = findViewById(R.id.passcodeEditText);
        String enteredPassword = passcodeBox.getText().toString();
        passcodeBox.setText("");

        try {
            if (!SettingsManager.getInstance(this).verifyLockscreenPassword(enteredPassword)) {
                Utilities.showErrorMessage(getString(R.string.wrong_lockscreen_password_error), this);
                return;
            }
            String decryptedEncryptionKey = SettingsManager.getInstance(this).getDecryptedEncryptionKey(enteredPassword, this);
            Intent newIntent = new Intent(this, MainActivity.class);
            newIntent.putExtra("encryption_key", decryptedEncryptionKey);
            startActivity(newIntent);
            finish();
        } catch (Exception e) {
            Utilities.showErrorMessage(e.getMessage(), this);
        }
    }
}
