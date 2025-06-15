package com.aidinhut.simpletextcrypt;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.content.ClipboardManager;
import android.content.Context;
import android.util.Log;
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

    private Long lastActivity;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        lastActivity = System.currentTimeMillis() / 1000;
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
            startActivity(new Intent(this, SettingsActivity.class));
            return true;
        }
        if (id == R.id.action_about) {
            showAbout();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void onEncryptButtonClicked(View view) {
        new CryptoTask(true).execute(getText());
    }

    public void onDecryptButtonClicked(View view) {
        new CryptoTask(false).execute(getText());
    }

    public void onCopyButtonClicked(View view) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("Locked Text", getText());
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

    public void onExitButtonClicked(View view) {
        Crypter.getInstance().clearCache();
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        for (int i = 1; i <= 50; i++) {
            ClipData clip = ClipData.newPlainText("Clear", String.valueOf(i));
            clipboard.setPrimaryClip(clip);
        }
        finish();
    }

    @Override
    protected void onResume() {
        int timeout = SettingsManager.getInstance(this).getLockTimeout(this);
        long currentTime = System.currentTimeMillis() / 1000;
        if (timeout != 0 && currentTime - lastActivity >= timeout * 60) {
            setText("");
            finish();
        } else {
            lastActivity = System.currentTimeMillis() / 1000;
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
        EditText textBox = findViewById(R.id.editText);
        return textBox.getText().toString();
    }

    private void setText(String input) {
        EditText textBox = findViewById(R.id.editText);
        textBox.setText(input);
    }

    private String getEncryptionKey() throws EncryptionKeyNotSet {
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
                getString(R.string.about_copyright),
                getString(R.string.about_source),
                getString(R.string.about_license_1),
                getString(R.string.about_license_2),
                getString(R.string.about_license_3)));
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

    private class CryptoTask extends AsyncTask<String, Void, String> {
        private final boolean isEncrypt;
        private Exception error;

        CryptoTask(boolean isEncrypt) {
            this.isEncrypt = isEncrypt;
        }

        @Override
        protected String doInBackground(String... params) {
            try {
                String input = params[0];
                String key = getEncryptionKey();
                long start = System.currentTimeMillis();
                String result = isEncrypt ? Crypter.getInstance().encrypt(key.toCharArray(), input) : Crypter.getInstance().decrypt(key.toCharArray(), input);
                Log.d("Crypto", (isEncrypt ? "Encryption" : "Decryption") + " time: " + (System.currentTimeMillis() - start) + " ms");
                return result;
            } catch (Exception e) {
                error = e;
                return null;
            }
        }

        @Override
        protected void onPostExecute(String result) {
            if (error != null) {
                Utilities.showErrorMessage(error.getMessage(), MainActivity.this);
            } else {
                setText(result);
            }
        }
    }
}
