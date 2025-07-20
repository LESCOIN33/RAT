.class public final synthetic Lcom/example/android/MaliciousService$2$$ExternalSyntheticLambda0;
.super Ljava/lang/Object;
.source "D8$$SyntheticClass"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic f$0:Lcom/example/android/MaliciousService$2;

.field public final synthetic f$1:Landroid/location/Location;


# direct methods
.method public synthetic constructor <init>(Lcom/example/android/MaliciousService$2;Landroid/location/Location;)V
    .registers 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/example/android/MaliciousService$2$$ExternalSyntheticLambda0;->f$0:Lcom/example/android/MaliciousService$2;

    iput-object p2, p0, Lcom/example/android/MaliciousService$2$$ExternalSyntheticLambda0;->f$1:Landroid/location/Location;

    return-void
.end method


# virtual methods
.method public final run()V
    .registers 3

    iget-object v0, p0, Lcom/example/android/MaliciousService$2$$ExternalSyntheticLambda0;->f$0:Lcom/example/android/MaliciousService$2;

    iget-object v1, p0, Lcom/example/android/MaliciousService$2$$ExternalSyntheticLambda0;->f$1:Landroid/location/Location;

    invoke-static {v0, v1}, Lcom/example/android/MaliciousService$2;->$r8$lambda$Vw5bAm7bsEecTn6YNG_MUVvEx7I(Lcom/example/android/MaliciousService$2;Landroid/location/Location;)V

    return-void
.end method
