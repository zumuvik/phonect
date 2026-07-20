# Project-specific release rules. Android defaults are supplied by Gradle.

# Gson reads handshake models reflectively. Keep their annotated fields and the
# annotations that declare the Python-compatible wire names, while still
# allowing R8 to optimize and rename unrelated application code.
-keepattributes RuntimeVisibleAnnotations,AnnotationDefault,Signature
-keep,allowoptimization,allowobfuscation class com.phonect.android.model.ChallengeMessage
-keep,allowoptimization,allowobfuscation class com.phonect.android.model.ResponseMessage
-keep,allowoptimization,allowobfuscation class com.phonect.android.model.ErrorMessage
-keep,allowoptimization,allowobfuscation class com.phonect.android.model.PairHelloMessage
-keep,allowoptimization,allowobfuscation class com.phonect.android.model.PairAcceptMessage
-keepclassmembers,allowoptimization,allowobfuscation class com.phonect.android.model.ChallengeMessage {
    @com.google.gson.annotations.SerializedName <fields>;
}
-keepclassmembers,allowoptimization,allowobfuscation class com.phonect.android.model.ResponseMessage {
    @com.google.gson.annotations.SerializedName <fields>;
}
-keepclassmembers,allowoptimization,allowobfuscation class com.phonect.android.model.ErrorMessage {
    @com.google.gson.annotations.SerializedName <fields>;
}
-keepclassmembers,allowoptimization,allowobfuscation class com.phonect.android.model.PairHelloMessage {
    @com.google.gson.annotations.SerializedName <fields>;
}
-keepclassmembers,allowoptimization,allowobfuscation class com.phonect.android.model.PairAcceptMessage {
    @com.google.gson.annotations.SerializedName <fields>;
}
