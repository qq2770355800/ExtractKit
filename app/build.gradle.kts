plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

android {
    namespace = "com.extractkit.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.extractkit.app"
        minSdk = 31
        targetSdk = 35
        versionCode = 214
        versionName = "9.26"
        resourceConfigurations += listOf("zh", "en")

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true           // R8：删未用代码（Compose 收益最大）
            isShrinkResources = true         // 删未引用的资源
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
        aidl = true
    }
    sourceSets {
        getByName("main").java.srcDirs("src/main/kotlin")
    }
    androidResources {
        noCompress += listOf("cve-2026-98260-uid0", "cve-2026-98260-android")
    }
    lint {
        // AGP 8.7 自带的 lint 解析不了 Kotlin 2.4 元数据，release 构建时关掉
        checkReleaseBuilds = false
        abortOnError = false
    }

    packaging {
        jniLibs.useLegacyPackaging = false
        resources {
            // 旧版把 8MB 的 .so 放在 assets 里；现在改存 .gz，这里兜底排除残留
            excludes += "assets/cve98937/libcve98937.so"
            excludes += setOf(
                "META-INF/*.version",
                "META-INF/*.kotlin_module",
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE*",
                "META-INF/NOTICE*",
                "DebugProbesKt.bin",
                "kotlin/**",
            )
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")

    // 真正的液态玻璃：直接编译 Kyant 的 backdrop 源码（:glass 模块）
    implementation(project(":glass"))
    implementation("androidx.compose.ui:ui:1.9.0")
    implementation("androidx.compose.foundation:foundation:1.9.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.compose.material3:material3:1.3.2")
    implementation("androidx.activity:activity-compose:1.9.3")
    configurations.all {
        resolutionStrategy {
            force("androidx.compose.ui:ui:1.9.0")
            force("androidx.compose.ui:ui-graphics:1.9.0")
            force("androidx.compose.runtime:runtime:1.9.0")
            force("androidx.compose.foundation:foundation:1.9.0")
        }
    }

    // 纯 JVM 单测：BTF / kallsyms / 配置生成（不依赖 Android）
    testImplementation("junit:junit:4.13.2")
}
