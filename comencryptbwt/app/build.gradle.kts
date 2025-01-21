plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.encrypt.bwt"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.encrypt.bwt"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        viewBinding = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.3"
    }

    buildTypes {
        getByName("release") {
            // Habilitamos ProGuard/R8
            isMinifyEnabled = true      // Para ofuscar el código
            isShrinkResources = true    // (Opcional) Quitar recursos no usados

            // Usamos el archivo ProGuard por defecto + nuestro archivo
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }

        // Si quieres un build "debug" sin ofuscar, no cambies nada aquí
    }
}

dependencies {
    implementation("com.google.code.findbugs:jsr305:3.0.2")
    // Core
    implementation("androidx.core:core-ktx:1.10.1")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.9.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")

    // Compose (opcional)
    implementation("androidx.activity:activity-compose:1.7.2")
    implementation("androidx.compose.ui:ui:1.5.3")
    implementation("androidx.compose.material:material:1.5.3")
    implementation("androidx.compose.material3:material3:1.2.0")
    implementation("androidx.compose.ui:ui-tooling-preview:1.5.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.6.1")
    debugImplementation("androidx.compose.ui:ui-tooling:1.5.3")

    // BouncyCastle u otras libs de cifrado
    implementation("org.bouncycastle:bcprov-jdk15on:1.70")

    // EncryptedSharedPreferences
    implementation("androidx.security:security-crypto:1.1.0-alpha03")

    // Gson para serializar/deserializar las claves
    implementation("com.google.code.gson:gson:2.10.1")

    // Librería ZXing para escaneo de QR
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("com.google.zxing:core:3.5.1")

    // Test
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}
