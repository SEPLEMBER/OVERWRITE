package com.aidinhut.simpletextcrypt;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Build;
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
import androidx.lifecycle.Lifecycle;
import android.text.util.Linkify;

import com.aidinhut.simpletextcrypt.exceptions.EncryptionKeyNotSet;

public class MainActivity extends AppCompatActivity {

    private Long lastActivity;
    private String encryptionKey;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        lastActivity = System.currentTimeMillis() / 1000;
        encryptionKey = getIntent().getStringExtra("encryption_key");
        if (encryptionKey == null) {
            startActivity(new Intent(this, LockActivity.class));
            finish();
        }
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
            Intent intent = new Intent(this, SettingsActivity.class);
            intent.putExtra("lockscreen_password", getIntent().getStringExtra("lockscreen_password"));
            startActivity(intent);
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && !isInForeground()) {
            Utilities.showErrorMessage(getString(R.string.clipboard_restricted), this);
            return;
        }
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("Encrypted Text", getText());
        clipboard.setPrimaryClip(clip);
    }

    public void onPasteButtonClicked(View view) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && !isInForeground()) {
            Utilities.showErrorMessage(getString(R.string.clipboard_restricted), this);
            return;
        }
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
        encryptionKey = null;
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        for (int i = 1; i <= 45; i++) {
            ClipData clip = ClipData.newPlainText("Clear", String.valueOf(i));
            clipboard.setPrimaryClip(clip);
        }
        Utilities.showErrorMessage(getString(R.string.clipboard_history_warning), this);
        finish();
    }

    @Override
    protected void onResume() {
        int timeout = SettingsManager.getInstance(this).getLockTimeout(this);
        long currentTime = System.currentTimeMillis() / 1000;
        if (timeout != 0 && currentTime - lastActivity >= timeout * 60) {
            setText("");
            encryptionKey = null;
            startActivity(new Intent(this, LockActivity.class));
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
            encryptionKey = null;
            startActivity(new Intent(this, LockActivity.class));
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
        if (encryptionKey == null || encryptionKey.isEmpty()) {
            throw new EncryptionKeyNotSet(this);
        }
        return encryptionKey;
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

    private boolean isInForeground() {
        return getLifecycle().getCurrentState().isAtLeast(Lifecycle.State.RESUMED);
    }

    private class CryptoTask extends AsyncTask<String, Void, String> {
        private final boolean isEncrypt;
        private Exception error;

        CryptoTask(boolean isEncrypt) {
            this.isEncrypt = this.isEncrypt;
        }

        @Override
        protected String doInBackground(String... params) {
            try {
                String input = params[0];
                String key = getEncryptionKey();
                long start = System.currentTimeMillis();
                String result = isEncrypt ? Crypter.getInstance().encrypt(key.toCharArray(), input) : Crypter.getInstance().decrypt(key.toCharArray(), input);
                return result;
            } catch (Exception e) {
                error = e;
                return null;
            }
        }

        @Override
        protected void onPostExecute(String result) {
            if (error != null) {
                setText("");
                Utilities.showErrorMessage(error.getMessage(), MainActivity.this);
            } else {
                setText(result);
            }
        }
    }
}
