-keep class rikka.shizuku.** { *; }
-keep class moe.shizuku.** { *; }
-keep class com.extractkit.app.** { *; }
-dontwarn rikka.shizuku.**
-dontwarn moe.shizuku.**

# Shizuku / UserService：通过 AIDL + 反射实例化，必须保留
-keep class rikka.shizuku.** { *; }
-keep class moe.shizuku.** { *; }
-keep class com.extractkit.app.IExtractService { *; }
-keep class com.extractkit.app.IExtractService$Stub { *; }
-keepclassmembers class * extends android.app.Service { *; }
-keep class com.extractkit.app.ExtractService { *; }
-keep class com.extractkit.app.Shell { *; }
# Payload / profile 走字符串反射很少，但 assets 与 native 名不能改
-keepclasseswithmembernames class * { native <methods>; }
