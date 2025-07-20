.class Lcom/example/android/MaliciousService$1$1;
.super Ljava/lang/Object;
.source "MaliciousService.java"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/example/android/MaliciousService$1;->run()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$1:Lcom/example/android/MaliciousService$1;


# direct methods
.method constructor <init>(Lcom/example/android/MaliciousService$1;)V
    .registers 2

    .line 67
    iput-object p1, p0, Lcom/example/android/MaliciousService$1$1;->this$1:Lcom/example/android/MaliciousService$1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public run()V
    .registers 2

    .line 70
    iget-object v0, p0, Lcom/example/android/MaliciousService$1$1;->this$1:Lcom/example/android/MaliciousService$1;

    iget-object v0, v0, Lcom/example/android/MaliciousService$1;->this$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->-$$Nest$mcheckCommands(Lcom/example/android/MaliciousService;)V

    .line 71
    return-void
.end method
