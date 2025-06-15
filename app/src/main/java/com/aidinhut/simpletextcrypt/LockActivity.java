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
        EditText passcodeBox = (EditText)findViewById(R.id.passcodeEditText);
        String passcode = passcodeBox.getText().toString();
        passcodeBox.setText("");

        String savedPasscode = SettingsManager.getInstance(this).getPasscode(this);

        if (savedPasscode.compareTo(passcode) != 0) {
            Utilities.showErrorMessage(getString(R.string.wrong_passcode_error), this);
            return;
        }

        Intent newIntent = new Intent(this, MainActivity.class);
        startActivity(newIntent);
    }
}
