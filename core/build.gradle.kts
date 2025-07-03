plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.lsparanoid)
    jacoco
}

android {
    namespace = "io.github.yoganataa.caster.core"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            enableUnitTestCoverage = true
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

dependencies {

    //core
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.okhttp)
    implementation(libs.gson)
    implementation(libs.hiddenapibypass)

    // testing
    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.inline)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.robolectric)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

tasks.create<JacocoReport>("jacocoTestReport") {
    group = "Reporting"
    description = "Generate Jacoco test coverage report for debug build"

    // Menentukan file .exec (hasil data coverage) yang akan digunakan
    executionData.setFrom(
        fileTree(buildDir) {
            include("outputs/unit_test_code_coverage/debugUnitTest/testDebugUnitTest.exec")
        }
    )

    // Menentukan direktori source code yang akan dianalisis
    sourceDirectories.setFrom(files("$projectDir/src/main/java"))

    // Menentukan file .class yang telah dikompilasi
    val kotlinClasses = fileTree("$buildDir/tmp/kotlin-classes/debug") {
        exclude(
            // Daftar file yang akan diabaikan dalam laporan coverage
            "**/R.class",
            "**/R$*.class",
            "**/BuildConfig.*",
            "**/Manifest*.*",
            "**/*_Args.class",
            "**/*_Args$*.class",
            "**/BR.class",
            "**/*_MembersInjector.class",
            "**/Dagger*Component.class",
            "**/Dagger*Component\$Builder.class",
            "**/*_Factory.class",
            "**/*_Provide*Factory.class",
            "**/*_ViewBinding*.*",
            "**/models/**", // Mengabaikan data class/model
            "**/logging/**" // Mengabaikan kelas logging
        )
    }
    classDirectories.setFrom(files(kotlinClasses))

    // Mengkonfigurasi output laporan
    reports {
        xml.required.set(true)   // Diperlukan untuk integrasi dengan CI/CD tools
        html.required.set(true)  // Laporan HTML yang mudah dibaca
        csv.required.set(false)
    }
}
