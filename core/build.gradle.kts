plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.lsparanoid)
    alias(libs.plugins.detekt)
    alias(libs.plugins.maven.publish)
    jacoco
}

android {
    namespace = "io.github.yoganataa.caster.core"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        testApplicationId = "io.github.yoganataa.caster.core.test"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            multiDexEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            enableUnitTestCoverage = true
            enableAndroidTestCoverage = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    sourceSets {
        getByName("androidTest") {
            manifest.srcFile("src/androidTest/AndroidManifest.xml")
        }
    }

    testOptions {
        unitTests.all {
            it.jvmArgs("-javaagent:${it.classpath.find { it.name.contains("mockito-core") }?.absolutePath}")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
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

    // Testing Libraries
    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.inline)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.robolectric)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.test.junit.ktx)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.mockk.android)
}

// Konfigurasi untuk mempublikasikan library ke Maven Local
publishing {
    publications {
        create<MavenPublication>("release") {
            // Menggunakan afterEvaluate untuk memastikan komponen Android sudah siap
            afterEvaluate {
                from(components["release"])
            }

            groupId = "io.github.yoganataa.caster"
            artifactId = "core"
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