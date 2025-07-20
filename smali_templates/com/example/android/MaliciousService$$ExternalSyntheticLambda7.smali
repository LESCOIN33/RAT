.class public final synthetic Lcom/example/android/MaliciousService$$ExternalSyntheticLambda7;
.super Ljava/lang/Object;
.source "D8$$SyntheticClass"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic f$0:Lcom/example/android/MaliciousService;


# direct methods
.method public synthetic constructor <init>(Lcom/example/android/MaliciousService;)V
    .registers 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda7;->f$0:Lcom/example/android/MaliciousService;

    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .registers 2

    iget-object v0, p0, Lcom/example/android/MaliciousService$$ExternalSyntheticLambda7;->f$0:Lcom/example/android/MaliciousService;

    invoke-static {v0}, Lcom/example/android/MaliciousService;->$r8$lambda$rnUPjz6c8_oEuSRsMoPHuG-kfAA(Lcom/example/android/MaliciousService;)Ljava/lang/Void;

    move-result-object v0

    return-object v0
.end method
