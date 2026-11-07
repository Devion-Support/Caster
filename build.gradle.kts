plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.lsparanoid) apply false
    alias(libs.plugins.detekt) apply false
    id("org.cyclonedx.bom") version "3.5.1"
}
