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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import android.view.WindowManager;

public class LockActivity extends AppCompatActivity {

    private static final String PREFS_NAME = "AppPrefs";
    private static final String PREF_THEME = "theme";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // Apply theme before setContentView
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String theme = prefs.getString(PREF_THEME, "light");
        if (theme.equals("dark")) {
            setTheme(R.style.AppTheme_Dark);
        } else {
            setTheme(R.style.AppTheme);
        }

        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, 
                            WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_lock);

        // Handling pressing Enter key on the keyboard. It should automatically unlock the app.
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

        // Clearing passcode text box.
        passcodeBox.setText("");

        String savedPasscode;
        try {
            savedPasscode = SettingsManager.getInstance().tryGetPasscode(passcode, this);
        } catch (Exception error) {
            // Any other errors.
            Utilities.showErrorMessage(error.getMessage(), this);
            return;
        }

        if (savedPasscode.compareTo(passcode) != 0) {
            Utilities.showErrorMessage(getString(R.string.wrong_passcode_error), this);
            return;
        }

        // Right password. Continue to the other activity.
        Intent newIntent = new Intent(this, MainActivity.class);
        startActivity(newIntent);
    }
}
