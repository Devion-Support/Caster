plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.lsparanoid)
    alias(libs.plugins.detekt)
    alias(libs.plugins.maven.publish)
    jacoco
}

android {
    namespace = "io.github.yoganataa.caster"
    compileSdk = 36

    defaultConfig {
        minSdk = 27
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
        multiDexEnabled = true
        testFunctionalTest = true
        testHandleProfiling = true
        signingConfig = signingConfigs.getByName("debug")
        
        // Add additional security configurations
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
        
        // Enable security features
        vectorDrawables.useSupportLibrary = true
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = false
            multiDexEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            consumerProguardFiles("consumer-rules.pro")
            
            // Security enhancements for release builds
            isJniDebuggable = false
            renderscriptOptimLevel = 3
            
            // Enable additional security features
            signingConfig = signingConfigs.getByName("debug") // In a real app, use a proper release signing config
        }
        debug {
            enableUnitTestCoverage = true
            enableAndroidTestCoverage = true
            
            // Add ProGuard files for debug builds to catch issues early
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            consumerProguardFiles("consumer-rules.pro")
            
            // Security settings for debug builds
            isJniDebuggable = false // Keep JNI debugging off even in debug builds
        }
    }

    // Add publishing configuration for release variant
    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
        }
    }

    sourceSets {
        getByName("androidTest") {
            manifest.srcFile("src/androidTest/AndroidManifest.xml")
        }
    }

    testOptions {
        targetSdk = 36
        unitTests.all {
            it.jvmArgs("-javaagent:${it.classpath.find { it.name.contains("mockito-core") }?.absolutePath}")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }
    
    buildFeatures {
        buildConfig = true
        // Remove Compose from library module
        compose = false
        viewBinding = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            // Exclude unnecessary files to reduce attack surface
            excludes += "META-INF/DEPENDENCIES"
            excludes += "META-INF/LICENSE"
            excludes += "META-INF/LICENSE.txt"
            excludes += "META-INF/license.txt"
            excludes += "META-INF/NOTICE"
            excludes += "META-INF/NOTICE.txt"
            excludes += "META-INF/notice.txt"
            excludes += "META-INF/ASL2.0"
            excludes += "META-INF/*.kotlin_module"
            excludes += "META-INF/proguard/androidx-annotations.pro"
            excludes += "META-INF/proguard/coroutines.pro"
        }
        
        jniLibs {
            // Enable JNI library compression
            useLegacyPackaging = false
        }
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
            isUniversalApk = false
        }
    }
    
    // Remove composeOptions since we're not using Compose
    /*
    composeOptions {
        kotlinCompilerExtensionVersion = libs.versions.composeCompiler.get()
    }
    */
    
    buildToolsVersion = "35.0.0"
    ndkVersion = "27.0.12077973"
    
    // Add additional security configurations
    lint {
        abortOnError = true
        checkReleaseBuilds = true
        checkDependencies = true
        ignoreWarnings = false
        quiet = false
        checkGeneratedSources = true
        sarifOutput = file("lint-report.sarif")
    }
}

dependencies {
    // Core Libraries
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.okhttp)
    implementation(libs.gson)
    implementation(libs.hiddenapibypass)
    implementation(libs.androidx.annotation)

    // Security Libraries
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.google.code.gson:gson:2.10.1")

    // Remove unnecessary test libraries
    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.inline)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.junit)
    testImplementation("com.google.truth:truth:1.1.3")
    testImplementation("androidx.test:core:1.5.0")
    testImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation(libs.androidx.junit)
}

// Konfigurasi untuk mempublikasikan library ke Maven Local
publishing {
    publications {
        create<MavenPublication>("release") {
            // Specify the release variant directly
            afterEvaluate {
                from(components["release"])
            }

            groupId = "io.github.yoganataa.caster"
            artifactId = "caster"
            version = "1.0.0"
        }
    }
    repositories {
        mavenLocal {
            // Menentukan lokasi repositori lokal, bisa disesuaikan jika perlu
            // name = "MyLocalRepo"
            // url = uri("${buildDir}/repo")
        }
    }
}


// --- Konfigurasi Jacoco ---
val jacocoExclusions = listOf(
    "**/R.class",
    "**/R$*.class",
    "**/BuildConfig.*",
    "**/Manifest*.*",
    "**/*Test*.*",
    "android/**/*.*",
    "**/databinding/*",
    "**/android/databinding/*",
    "**/androidx/databinding/*",
    "**/*_MembersInjector.class",
    "**/Dagger*Component.class",
    "**/Dagger*Component\$Builder.class",
    "**/*_Factory.class",
    "**/*_Provide*Factory.class",
    "**/*_ViewBinding*.*",
    "**/models/**",
    "**/logging/**"
)

tasks.register<JacocoReport>("jacocoUnitTestReport") {
    group = "Reporting"
    description = "Generate Jacoco coverage report for unit tests."

    dependsOn("testDebugUnitTest")

    reports {
        xml.required.set(true)
        html.required.set(true)
        csv.required.set(false)
    }

    sourceDirectories.setFrom(files("$projectDir/src/main/java", "$projectDir/src/main/kotlin"))

    classDirectories.setFrom(files(
        fileTree(layout.buildDirectory.dir("tmp/kotlin-classes/debug")) { exclude(jacocoExclusions) },
        fileTree(layout.buildDirectory.dir("classes/kotlin/debug")) { exclude(jacocoExclusions) }
    ))
    executionData.setFrom(
        files(
            layout.buildDirectory.file("jacoco/testDebugUnitTest.exec")
        )
    )
}

tasks.register<JacocoReport>("jacocoTestReport") {
    group = "Reporting"
    description = "Generate Jacoco coverage report for all tests (unit and instrumentation)."

    dependsOn("testDebugUnitTest", "createDebugCoverageReport")

    reports {
        xml.required.set(true)
        html.required.set(true)
        csv.required.set(false)
    }

    sourceDirectories.setFrom(files("$projectDir/src/main/java", "$projectDir/src/main/kotlin"))

    classDirectories.setFrom(files(
        fileTree(layout.buildDirectory.dir("tmp/kotlin-classes/debug")) { exclude(jacocoExclusions) },
        fileTree(layout.buildDirectory.dir("classes/kotlin/debug")) { exclude(jacocoExclusions) }
    ))
    executionData.setFrom(
        files(
            layout.buildDirectory.file("jacoco/testDebugUnitTest.exec"),
            layout.buildDirectory.file("outputs/code_coverage/debugAndroidTest/connected/coverage.ec")
        )
    )
}