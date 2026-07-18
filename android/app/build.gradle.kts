plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

fun signingInput(name: String): String? = providers.gradleProperty(name).orNull
    ?: providers.environmentVariable(name).orNull

val releaseSigningInputs = listOf(
    "ANDROID_KEYSTORE_PATH", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_ALIAS", "ANDROID_KEY_PASSWORD",
).associateWith(::signingInput)
val releaseKeystore = releaseSigningInputs["ANDROID_KEYSTORE_PATH"]?.let(::file)
val hasReleaseSigning = releaseSigningInputs.values.all { !it.isNullOrBlank() } && releaseKeystore?.isFile == true

android {
    namespace = "com.phonect.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.phonect.android"
        minSdk = 28          // Android 9 — BiometricPrompt available
        targetSdk = 34
        versionCode = 10
        versionName = "0.4.8"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (hasReleaseSigning) create("release") {
            storeFile = releaseKeystore
            storePassword = releaseSigningInputs.getValue("ANDROID_KEYSTORE_PASSWORD")
            keyAlias = releaseSigningInputs.getValue("ANDROID_KEY_ALIAS")
            keyPassword = releaseSigningInputs.getValue("ANDROID_KEY_PASSWORD")
        }
    }

    buildTypes {
        getByName("debug") {
            applicationIdSuffix = ".debug"
        }

        release {
            isMinifyEnabled = true
            if (hasReleaseSigning) signingConfig = signingConfigs.getByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
    }
}

tasks.matching { it.name.contains("Release", ignoreCase = true) }.configureEach {
    doFirst {
        val missing = releaseSigningInputs.filterValues { it.isNullOrBlank() }.keys
        require(missing.isEmpty()) { "Release signing requires: ${missing.joinToString(", ")}" }
        require(file(releaseSigningInputs.getValue("ANDROID_KEYSTORE_PATH")!!).isFile) {
            "Release signing keystore does not exist: ANDROID_KEYSTORE_PATH"
        }
    }
}

dependencies {
    // Material Components
    implementation("com.google.android.material:material:1.11.0")

    // Core
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.activity:activity-compose:1.8.2")

    // Foreground Service + notifications
    implementation("androidx.core:core:1.12.0")

    // Biometric
    implementation("androidx.biometric:biometric:1.2.0-alpha05")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")

    // JSON serialisation
    implementation("com.google.code.gson:gson:2.10.1")

    // Testing
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.7.3")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
}
