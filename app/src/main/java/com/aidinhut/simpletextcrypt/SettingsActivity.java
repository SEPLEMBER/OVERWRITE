package com.aidinhut.simpletextcrypt;

import android.app.AlertDialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
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
        EditText encryptionKeyTextBox = (EditText)findViewById(R.id.encryptionKeyEditText);
        EditText passcodeTextBox = (EditText)findViewById(R.id.passcodeEditText);
        EditText lockTimeoutTextBox = (EditText)findViewById(R.id.lockTimeoutEditText);

        if (encryptionKeyTextBox.getText().toString().length() < 8) {
            Utilities.showErrorMessage(getString(R.string.invalid_key_length_error), this);
            return;
        }
        if (passcodeTextBox.getText().toString().length() < 2) {
            Utilities.showErrorMessage(getString(R.string.invalid_passcode_error), this);
            return;
        }

        try {
            SettingsManager.getInstance(this).setPasscode(passcodeTextBox.getText().toString(), this);
            SettingsManager.getInstance(this).setEncryptionKey(encryptionKeyTextBox.getText().toString(), this);
            SettingsManager.getInstance(this).setLockTimeout(lockTimeoutTextBox.getText().toString(), this);
        } catch (Exception error) {
            Utilities.showErrorMessage(error.getMessage(), this);
            return;
        }

        finish();
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
            encryptionKeyTextBox.setText(SettingsManager.getInstance(this).getEncryptionKey(this));
            passcodeTextBox.setText(SettingsManager.getInstance(this).getPasscode(this));
            lockTimeoutTextBox.setText(Integer.toString(SettingsManager.getInstance(this).getLockTimeout(this)));
        } catch (Exception error) {
            Utilities.showErrorMessage(error.getMessage(), this);
        }
    }
}
