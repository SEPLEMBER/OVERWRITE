package com.aidinhut.simpletextcrypt;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.text.util.LinkifyCompat;
import android.text.util.Linkify;

import com.aidinhut.simpletextcrypt.exceptions.EncryptionKeyNotSet;

public class MainActivity extends AppCompatActivity {

    Long lastActivity;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        this.lastActivity = System.currentTimeMillis() / 1000;
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.action_settings) {
            Intent settingsIntent = new Intent(this, SettingsActivity.class);
            startActivity(settingsIntent);
            return true;
        }

        if (id == R.id.action_about) {
            showAbout();
        }

        return super.onOptionsItemSelected(item);
    }

    public void onEncryptButtonClicked(View view) {
        try {
            String key = getEncryptionKey();
            setText(Crypter.encrypt(key.toCharArray(), getText()));
        } catch (Exception error) {
            Utilities.showErrorMessage(error.getMessage(), this);
        }
    }

    public void onDecryptButtonClicked(View view) {
        try {
            String key = getEncryptionKey();
            setText(Crypter.decrypt(key.toCharArray(), getText()));
        } catch (Exception error) {
            Utilities.showErrorMessage(error.getMessage(), this);
        }
    }

    public void onCopyButtonClicked(View view) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("Encrypted Text", getText());
        clipboard.setPrimaryClip(clip);
    }

    public void onPasteButtonClicked(View view) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard.hasPrimaryClip()) {
            ClipData.Item item = clipboard.getPrimaryClip().getItemAt(0);
            if (item.getText() != null) {
                setText(item.getText().toString());
            }
        }
    }

    public void onClearButtonClicked(View view) {
        setText("");
    }

    @Override
    protected void onResume() {
        int timeout = SettingsManager.getInstance(this).getLockTimeout(this);
        long currentTime = System.currentTimeMillis() / 1000;
        if (timeout != 0 && currentTime - lastActivity >= timeout * 60) {
            setText("");
            finish();
        } else {
            this.lastActivity = System.currentTimeMillis() / 1000;
        }
        super.onResume();
    }

    @Override
    protected void onPause() {
        int timeout = SettingsManager.getInstance(this).getLockTimeout(this);
        long currentTime = System.currentTimeMillis() / 1000;
        if (timeout == 0 || currentTime - lastActivity >= timeout * 60) {
            setText("");
            finish();
        }
        super.onPause();
    }

    private String getText() {
        EditText textBox = (EditText) findViewById(R.id.editText);
        return textBox.getText().toString();
    }

    private void setText(String input) {
        EditText textBox = (EditText) findViewById(R.id.editText);
        textBox.setText(input);
    }

    private String getEncryptionKey() throws UnsupportedEncodingException,
            GeneralSecurityException, EncryptionKeyNotSet {
        String encKey = SettingsManager.getInstance(this).getEncryptionKey(this);
        if (encKey.isEmpty()) {
            throw new EncryptionKeyNotSet(this);
        }
        return encKey;
    }

    private void showAbout() {
        TextView messageTextView = new TextView(this);
        messageTextView.setLinksClickable(true);
        LinkifyCompat.addLinks(messageTextView, Linkify.WEB_URLS);
        messageTextView.setText(String.format("%s\n\n%s\n\n%s\n%s\n\n%s",
                this.getString(R.string.about_copyright),
                this.getString(R.string.about_source),
                this.getString(R.string.about_license_1),
                this.getString(R.string.about_license_2),
                this.getString(R.string.about_license_3)));
        messageTextView.setPadding(10, 10, 10, 10);
        messageTextView.setGravity(Gravity.CENTER);

        ScrollView scrollView = new ScrollView(this);
        scrollView.addView(messageTextView);

        AlertDialog.Builder dialogBuilder = new AlertDialog.Builder(this);
        dialogBuilder.setView(scrollView);
        dialogBuilder.setPositiveButton("OK", null);
        dialogBuilder.setCancelable(true);

        dialogBuilder.show();
    }
}
