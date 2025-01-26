// filename: EncryptDecryptHelper.kt
package com.encrypt.bwt

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object EncryptDecryptHelper {

    // =======================================================
    // ============== PARÁMETROS GLOBALES DE PBKDF2 ==========
    // =======================================================
    private const val PBKDF2_ITERATIONS = 100_000
    private const val KEY_SIZE_BITS = 256 // Ahora 256 bits
    private const val SALT_SIZE = 16
    private const val IV_SIZE_GCM = 12  // IV(Nonce) para GCM
    // (Para XChaCha20 se suelen usar 24 bytes, no lo detallamos aquí salvo que quieras implementarlo)

    // =======================================================
    // ============== AES usando GCM + PBKDF2 (256 bits) =====
    // =======================================================
    /**
     * Cifra un texto con AES/GCM/NoPadding (clave 256 bits).
     * Usamos PBKDF2 (HmacSHA256) con 100,000 iteraciones.
     * Guardamos SALT(16) + IV(12) + ciphertext+tag => Base64.
     */
    fun encryptAES(plainText: String, password: String): String {
        val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
        val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS)

        val iv = ByteArray(IV_SIZE_GCM).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv) // Tag = 128 bits
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        val cipherBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        val combined = ByteArray(salt.size + iv.size + cipherBytes.size)
        System.arraycopy(salt, 0, combined, 0, salt.size)
        System.arraycopy(iv, 0, combined, salt.size, iv.size)
        System.arraycopy(cipherBytes, 0, combined, salt.size + iv.size, cipherBytes.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    /**
     * Descifra con AES/GCM/NoPadding (clave 256 bits).
     * Espera Base64( SALT(16) + IV(12) + ciphertext+tag ).
     */
    fun decryptAES(base64Cipher: String, password: String): String {
        val allBytes = Base64.decode(base64Cipher, Base64.NO_WRAP)
        if (allBytes.size < SALT_SIZE + IV_SIZE_GCM) {
            return "Error: datos inválidos."
        }
        val salt = allBytes.copyOfRange(0, SALT_SIZE)
        val iv = allBytes.copyOfRange(SALT_SIZE, SALT_SIZE + IV_SIZE_GCM)
        val cipherBytes = allBytes.copyOfRange(SALT_SIZE + IV_SIZE_GCM, allBytes.size)

        val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        val plainBytes = cipher.doFinal(cipherBytes)
        return String(plainBytes, Charsets.UTF_8)
    }

    // =======================================================
    // ============== CAMELLIA (GCM/NoPadding) ===============
    // =======================================================
    /**
     * Cifra con Camellia/GCM/NoPadding (256 bits).
     * Estructura: SALT(16) + IV(12) + ciphertext+tag => Base64
     */
    fun encryptCamellia(plainText: String, password: String): String {
        val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
        val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS, "Camellia")

        val iv = ByteArray(IV_SIZE_GCM).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("Camellia/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        val cipherBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        val combined = ByteArray(salt.size + iv.size + cipherBytes.size)
        System.arraycopy(salt, 0, combined, 0, salt.size)
        System.arraycopy(iv, 0, combined, salt.size, iv.size)
        System.arraycopy(cipherBytes, 0, combined, salt.size + iv.size, cipherBytes.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    /**
     * Descifra con Camellia/GCM/NoPadding (256 bits).
     * Espera: Base64( SALT(16) + IV(12) + ciphertext+tag ).
     */
    fun decryptCamellia(base64Cipher: String, password: String): String {
        val allBytes = Base64.decode(base64Cipher, Base64.NO_WRAP)
        if (allBytes.size < SALT_SIZE + IV_SIZE_GCM) {
            return "Error: datos inválidos."
        }
        val salt = allBytes.copyOfRange(0, SALT_SIZE)
        val iv = allBytes.copyOfRange(SALT_SIZE, SALT_SIZE + IV_SIZE_GCM)
        val cipherBytes = allBytes.copyOfRange(SALT_SIZE + IV_SIZE_GCM, allBytes.size)

        val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS, "Camellia")

        val cipher = Cipher.getInstance("Camellia/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        val plainBytes = cipher.doFinal(cipherBytes)
        return String(plainBytes, Charsets.UTF_8)
    }

    // =======================================================
    // ============== ChaCha20-Poly1305 ======================
    // =======================================================
    /**
     * Cifra con ChaCha20-Poly1305 (256 bits).
     * Estructura: SALT(16) + NONCE(12) + ciphertext+tag => Base64
     */
    fun encryptChaCha20Poly1305(plainText: String, password: String): String {
        val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
        val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS, "ChaCha20")
        // Nota: El "algorithm" de la SecretKeySpec no siempre importa, pero lo indicamos para referencia.

        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) } // ChaCha20-Poly1305 espera 12 bytes
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)

        val cipherBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        val combined = ByteArray(salt.size + nonce.size + cipherBytes.size)
        System.arraycopy(salt, 0, combined, 0, salt.size)
        System.arraycopy(nonce, 0, combined, salt.size, nonce.size)
        System.arraycopy(cipherBytes, 0, combined, salt.size + nonce.size, cipherBytes.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    /**
     * Descifra con ChaCha20-Poly1305 (256 bits).
     * Espera: Base64( SALT(16) + NONCE(12) + ciphertext+tag ).
     */
    fun decryptChaCha20Poly1305(base64Cipher: String, password: String): String {
        val allBytes = Base64.decode(base64Cipher, Base64.NO_WRAP)
        if (allBytes.size < SALT_SIZE + 12) {
            return "Error: datos inválidos."
        }
        val salt = allBytes.copyOfRange(0, SALT_SIZE)
        val nonce = allBytes.copyOfRange(SALT_SIZE, SALT_SIZE + 12)
        val cipherBytes = allBytes.copyOfRange(SALT_SIZE + 12, allBytes.size)

        val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS, "ChaCha20")

        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        val plainBytes = cipher.doFinal(cipherBytes)
        return String(plainBytes, Charsets.UTF_8)
    }

    // =======================================================
    // ============== PBKDF2 para derivar la key =============
    // =======================================================
    private fun deriveKeyPBKDF2(
        password: String,
        salt: ByteArray,
        keySizeBits: Int,
        algorithmForKeySpec: String = "AES"
    ): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(
            password.toCharArray(),
            salt,
            PBKDF2_ITERATIONS,
            keySizeBits
        )
        val tmp = factory.generateSecret(spec)
        return SecretKeySpec(tmp.encoded, algorithmForKeySpec)
    }

    // =======================================================
    // ===================== DES (ECB/PKCS5) =================
    // =======================================================
    fun encryptDES(plainText: String, key: String): String {
        val secretKey = generateDESKey(key)
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
    }

    fun decryptDES(cipherText: String, key: String): String {
        val secretKey = generateDESKey(key)
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        val decryptedBytes = cipher.doFinal(Base64.decode(cipherText, Base64.NO_WRAP))
        return String(decryptedBytes, Charsets.UTF_8)
    }

    private fun generateDESKey(key: String): javax.crypto.SecretKey {
        val keyBytes = key.toByteArray(Charsets.UTF_8).copyOf(8)
        return SecretKeySpec(keyBytes, "DES")
    }
}
