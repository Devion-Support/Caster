# Add project specific ProGuard rules here.
# By default, the Android Gradle plugin provides a default ProGuard file named
# proguard-android-optimize.txt which is applied automatically.
# You can also load more rules from external files or expertise.

# --- General Obfuscation Enhancements ---

# Keep all classes that implement Parcelable and their CREATOR field.
# This is crucial for inter-process communication and saving instance state.
-keep class * implements android.os.Parcelable {
  public static final android.os.Parcelable$Creator CREATOR;
}

# Keep all classes that implement java.io.Serializable.
# This is important for serialization/deserialization operations.
-keep class * implements java.io.Serializable {
  static <fields>;
  <fields>;
  <methods>;
}

# Keep enum classes and their values.
# Enums are often used in switch statements or accessed by name.
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# For methods that are called from JNI (e.g. C/C++ code), keep their names
# and signatures.
-keepclassmembers class * {
    native <methods>;
}

# If your project uses WebView with JavaScript, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# --- End of General Obfuscation Enhancements ---

# Add any other specific rules for your application here.
# For example, if you use a third-party library that uses reflection,
# you might need to add rules to keep its classes and members.
