package com.aidinhut.simpletextcrypt;

import android.app.AlertDialog;
import android.content.Context;

public class Utilities {
    public static void showErrorMessage(String message, Context context) {
        AlertDialog.Builder dlgAlert = new AlertDialog.Builder(context);
        dlgAlert.setMessage(message);
        dlgAlert.setTitle(context.getString(R.string.error_title));
        dlgAlert.setPositiveButton("OK", null);
        dlgAlert.setCancelable(true);
        dlgAlert.show();
    }
}
