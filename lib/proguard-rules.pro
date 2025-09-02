# Add project specific ProGuard rules here.
# For more details, see http://developer.android.com/guide/developing/tools/proguard.html

# Package and class obfuscation
-repackageclasses 'io.github.yoganataa.caster.internal'
-allowaccessmodification
-renamesourcefileattribute SourceFile
-overloadaggressively
-mergeinterfacesaggressively
-flattenpackagehierarchy 'io.github.yoganataa.caster.internal'

# Optimization settings
-optimizationpasses 5
-optimizations !code/simplification/arithmetic,!field/*,!class/merging/*,code/allocation/variable
-dontusemixedcaseclassnames
-dontpreverify
-verbose

# Print information
-printmapping mapping.txt
-printseeds seeds.txt
-printusage unused.txt

# Keep important attributes
-keepattributes Signature,InnerClasses,EnclosingMethod
-keepattributes Exceptions,SourceFile,LineNumberTable,*Annotation*,Code

# Keep our package content
-keep class io.github.yoganataa.caster.** { *; }
-keep interface io.github.yoganataa.caster.** { *; }
-keep enum io.github.yoganataa.caster.** { *; }

# Keep annotation-based rules
-keep @interface io.github.yoganataa.caster.Keep
-keep @io.github.yoganataa.caster.Keep class *
-keepclassmembers class * {
    @io.github.yoganataa.caster.Keep *;
}

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep standard Java/Android components
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator CREATOR;
}

-keepnames class * implements java.io.Serializable
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# Remove logging and debugging code
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
    public static *** wtf(...);
}

-assumenosideeffects class java.io.PrintStream {
    public void print(...);
    public void println(...);
}

-assumenosideeffects class java.lang.Throwable {
    public void printStackTrace();
}

-assumenosideeffects class java.lang.AssertionError {
    <init>();
    <init>(java.lang.Object);
}

# Keep essential libraries
-keep class java.security.** { *; }
-keep class javax.crypto.** { *; }
-keep class javax.net.ssl.** { *; }
-keep class android.security.** { *; }
-keep class kotlinx.coroutines.** { *; }
-keep class kotlin.coroutines.** { *; }
-keep class okhttp3.** { *; }
-keep class okio.** { *; }
-keep class com.google.gson.** { *; }
-keep class androidx.** { *; }
-keep class android.annotation.** { *; }
-keep class androidx.annotation.** { *; }

# Keep testing libraries for debug builds
-keep class org.junit.** { *; }
-keep class org.mockito.** { *; }
-keep class androidx.test.** { *; }

# Keep necessary reflection APIs for security checks
-keepclassmembers class java.lang.Class {
    public java.lang.String getName();
    public java.lang.ClassLoader getClassLoader();
    public java.lang.Class getSuperclass();
    public java.lang.reflect.Method[] getDeclaredMethods();
    public java.lang.reflect.Field[] getDeclaredFields();
    public java.lang.reflect.Constructor[] getDeclaredConstructors();
}

-keepclassmembers class java.lang.reflect.** {
    public <init>(...);
    public *** get*(...);
    public *** set*(...);
    public *** invoke*(...);
}

# Keep view-related classes
-keepclassmembers class * extends android.view.View {
    public <init>(android.content.Context);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context, android.util.AttributeSet, int);
    *** get*();
    void set*(***);
}

# Keep activity classes
-keepclassmembers class * extends android.app.Activity {
    public void *(android.view.View);
}

# Keep fragment classes
-keepclassmembers class * extends android.app.Fragment {
    public void *(android.view.View);
}

-keepclassmembers class * extends androidx.fragment.app.Fragment {
    public void *(android.view.View);
}

# Keep service classes
-keepclassmembers class * extends android.app.Service {
    public void *(android.view.View);
}

# Keep broadcast receiver classes
-keepclassmembers class * extends android.content.BroadcastReceiver {
    public void *(android.view.View);
}

# Keep content provider classes
-keepclassmembers class * extends android.content.ContentProvider {
    public void *(android.view.View);
}

# Keep application classes
-keepclassmembers class * extends android.app.Application {
    public void *(android.view.View);
}

# Keep classes with specific annotations
-keep @interface io.github.yoganataa.caster.Keep
-keep @io.github.yoganataa.caster.Keep class *
-keepclassmembers class * {
    @io.github.yoganataa.caster.Keep *;
}

# Keep all classes in our package
-keep class io.github.yoganataa.caster.** { *; }
-keep interface io.github.yoganataa.caster.** { *; }
-keep enum io.github.yoganataa.caster.** { *; }

# Security-specific rules
# Obfuscate logging calls
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
}

# Remove assertion checks
-assumenosideeffects class java.lang.AssertionError {
    <init>();
    <init>(java.lang.Object);
}

# Remove debugging code
-assumenosideeffects class android.os.Debug {
    public static void waitForDebugger();
    public static boolean isDebuggerConnected();
}

# Remove trace calls
-assumenosideeffects class android.os.Trace {
    public static void beginSection(java.lang.String);
    public static void endSection();
}

# Remove strict mode calls
-assumenosideeffects class android.os.StrictMode {
    public static void enableDefaults();
    public static void setThreadPolicy(android.os.StrictMode$ThreadPolicy);
    public static void setVmPolicy(android.os.StrictMode$VmPolicy);
}

# Security hardening rules
# Prevent reflection attacks by keeping only necessary reflection APIs
-keepclassmembers class java.lang.Class {
    public java.lang.String getName();
    public java.lang.ClassLoader getClassLoader();
    public java.lang.Class getSuperclass();
    public java.lang.reflect.Method[] getDeclaredMethods();
    public java.lang.reflect.Field[] getDeclaredFields();
    public java.lang.reflect.Constructor[] getDeclaredConstructors();
}

# Keep necessary reflection APIs for security checks
-keepclassmembers class java.lang.reflect.** {
    public <init>(...);
    public *** get*(...);
    public *** set*(...);
    public *** invoke*(...);
}

# Keep security-related classes
-keep class java.security.** { *; }
-keep class javax.crypto.** { *; }
-keep class javax.net.ssl.** { *; }

# Keep Android security classes
-keep class android.security.** { *; }
-keep class android.security.keystore.** { *; }
-keep class android.security.identity.** { *; }

# Keep network security classes
-keep class android.net.** { *; }
-keep class android.net.http.** { *; }
-keep class android.net.ssl.** { *; }

# Keep necessary classes for Caster functionality
-keep class io.github.yoganataa.caster.** { *; }

# Obfuscate third-party libraries more aggressively
-repackageclasses io.github.yoganataa.caster.internal
-overloadaggressively

# Remove unnecessary debug information from third-party libraries
-assumenosideeffects class com.google.gson.** {
    public static void setLogger(...);
}

# Security enhancements for Kotlin
-assumenosideeffects class kotlin.jvm.internal.Intrinsics {
    public static void checkParameterIsNotNull(...);
    public static void checkExpressionValueIsNotNull(...);
    public static void checkReturnedValueIsNotNull(...);
    public static void checkFieldIsNotNull(...);
}

# Remove Kotlin assertion checks
-assumenosideeffects class kotlin.jvm.internal.Intrinsics {
    public static void throwAssert(...);
}

# Security rules for coroutines
-keep class kotlinx.coroutines.** { *; }
-keep class kotlin.coroutines.** { *; }

# Security rules for OkHttp
-keep class okhttp3.** { *; }
-keep class okio.** { *; }

# Security rules for Gson
-keep class com.google.gson.** { *; }

# Security rules for HiddenApiBypass
-keep class org.lsposed.hiddenapibypass.** { *; }

# Security rules for AndroidX
-keep class androidx.** { *; }

# Security rules for annotations
-keep class android.annotation.** { *; }
-keep class androidx.annotation.** { *; }

# Security rules for testing (only applicable in debug builds)
# Note: ProGuard doesn't have conditional directives, these rules will be applied based on build type in build.gradle
-keep class org.junit.** { *; }
-keep class org.mockito.** { *; }
-keep class org.robolectric.** { *; }
-keep class androidx.test.** { *; }
-keep class com.google.common.truth.** { *; }

# Enhanced obfuscation rules for additional security
# Flatten package structure
-flattenpackagehierarchy

# Use aggressive optimization
-optimizations !code/simplification/arithmetic,!field/*,!class/merging/*

# Optimize aggressively
-optimizationpasses 5

# Allow access modification
-allowaccessmodification

# Remove debug information
# -dontdebug  # This is not a valid option, removing it

# Remove line numbers
-dontusemixedcaseclassnames

# Preverify the code
-dontpreverify

# Verbose output
-verbose

# Print mapping to file
-printmapping mapping.txt

# Print seeds to file
-printseeds seeds.txt

# Print unused code to file
-printusage unused.txt

# Keep line numbers for debugging (remove in production)
-keepattributes SourceFile,LineNumberTable

# Additional obfuscation for native methods
-keepclasseswithmembers class * {
    native <methods>;
}

# Keep constructors for serializable classes
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# Keep enum methods
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Keep annotations
-keepattributes *Annotation*

# Keep generic signatures
-keepattributes Signature

# Keep enclosing methods
-keepattributes EnclosingMethod

# Keep runtime visible annotations
-keepattributes RuntimeVisibleAnnotations

# Keep runtime invisible annotations
-keepattributes RuntimeInvisibleAnnotations

# Keep runtime visible parameter annotations
-keepattributes RuntimeVisibleParameterAnnotations

# Keep runtime invisible parameter annotations
-keepattributes RuntimeInvisibleParameterAnnotations

# Keep annotation default values
-keepattributes AnnotationDefault

# Keep local variable tables
-keepattributes LocalVariableTable

# Keep local variable type tables
-keepattributes LocalVariableTypeTable

# Keep code attributes
-keepattributes Code

# Keep deprecated members
-keepattributes Deprecated

# Keep synthetic members
-keepattributes Synthetic

# Keep bridge methods
-keepattributes Bridge

# Keep stack map tables
-keepattributes StackMapTable

# Keep exception table
-keepattributes ExceptionTable

# Keep inner classes
-keepattributes InnerClasses

# Keep parameter annotations
-keepattributes ParameterAnnotations

# Keep method parameters
-keepattributes MethodParameters

# Keep module information
-keepattributes Module

# Keep module packages
-keepattributes ModulePackages

# Keep module main class
-keepattributes ModuleMainClass

# Keep nest host
-keepattributes NestHost

# Keep nest members
-keepattributes NestMembers

# Keep record
-keepattributes Record

# Keep permitted subclasses
-keepattributes PermittedSubclasses

# Keep sealed classes
-keepattributes SealedClasses

# Additional security obfuscation rules
# Obfuscate string constants (use with caution)
# -obfuscatestringconstants

# Use custom dictionary for class names
# -classobfuscationdictionary proguard-dictionary.txt

# Use custom dictionary for package names
# -packageobfuscationdictionary proguard-dictionary.txt

# Use custom dictionary for method names
-overloadaggressively

# Merge interfaces aggressively
-mergeinterfacesaggressively

# Optimize with all optimizations
-optimizations code/allocation/variable

# Remove logging calls
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
    public static *** wtf(...);
}

# Remove System.out and System.err calls
-assumenosideeffects class java.io.PrintStream {
    public void print(...);
    public void println(...);
}

# Remove Throwable.printStackTrace() calls
-assumenosideeffects class java.lang.Throwable {
    public void printStackTrace();
}

# Remove assertion checks
-assumenosideeffects class java.lang.AssertionError {
    <init>();
    <init>(java.lang.Object);
}

# Remove debugging code
-assumenosideeffects class android.os.Debug {
    public static void waitForDebugger();
    public static boolean isDebuggerConnected();
    public static void startMethodTracing*(...);
    public static void stopMethodTracing();
}

# Remove trace calls
-assumenosideeffects class android.os.Trace {
    public static void beginSection(java.lang.String);
    public static void endSection();
    public static void beginAsyncSection(java.lang.String, int);
    public static void endAsyncSection(java.lang.String, int);
    public static void setCounter(java.lang.String, long);
}

# Remove strict mode calls
-assumenosideeffects class android.os.StrictMode {
    public static void enableDefaults();
    public static void setThreadPolicy(android.os.StrictMode$ThreadPolicy);
    public static void setVmPolicy(android.os.StrictMode$VmPolicy);
    public static android.os.StrictMode$ThreadPolicy getThreadPolicy();
    public static android.os.StrictMode$VmPolicy getVmPolicy();
}

# Remove debugging methods from Build class
-assumenosideeffects class android.os.Build {
    public static boolean isDebuggingEnabled();
}

# Remove debugging methods from Application class
-assumenosideeffects class android.app.Application {
    public static boolean isDebuggable();
}

# Remove debugging methods from Activity class
-assumenosideeffects class android.app.Activity {
    public boolean isDebuggable();
}

# Remove debugging methods from Service class
-assumenosideeffects class android.app.Service {
    public boolean isDebuggable();
}

# Remove debugging methods from BroadcastReceiver class
-assumenosideeffects class android.content.BroadcastReceiver {
    public boolean isDebuggable();
}

# Remove debugging methods from ContentProvider class
-assumenosideeffects class android.content.ContentProvider {
    public boolean isDebuggable();
}

# Remove debugging methods from ApplicationInfo class
-assumenosideeffects class android.content.pm.ApplicationInfo {
    public boolean isDebuggable();
}

# Remove debugging methods from PackageInfo class
-assumenosideeffects class android.content.pm.PackageInfo {
    public boolean isDebuggable();
}