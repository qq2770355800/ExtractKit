plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.kyant.backdrop"
    compileSdk = 35
    defaultConfig { minSdk = 31 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin {
        compilerOptions { freeCompilerArgs.add("-Xcontext-parameters") }
    }
    buildFeatures { compose = true }
    sourceSets { getByName("main").java.srcDirs("src/main/kotlin") }
}

dependencies {
    implementation("androidx.compose.ui:ui:1.9.0")
    implementation("androidx.compose.ui:ui-graphics:1.9.0")
    implementation("androidx.compose.foundation:foundation:1.9.0")
    implementation("androidx.compose.runtime:runtime:1.9.0")
    implementation("org.jetbrains:annotations:23.0.0")
    configurations.all {
        resolutionStrategy {
            force("androidx.compose.ui:ui:1.9.0")
            force("androidx.compose.ui:ui-graphics:1.9.0")
            force("androidx.compose.runtime:runtime:1.9.0")
            force("androidx.compose.foundation:foundation:1.9.0")
        }
    }
}
