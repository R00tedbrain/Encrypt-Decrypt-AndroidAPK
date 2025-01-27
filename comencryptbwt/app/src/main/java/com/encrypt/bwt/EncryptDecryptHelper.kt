// filename: EncryptDecryptHelper.kt
package com.encrypt.bwt

import android.util.Base64
import com.encrypt.bwt.aegis.Aegis256
import com.encrypt.bwt.aegis.VerificationFailedException
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.SecureRandom
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object EncryptDecryptHelper {

    init {
        // Asegurarnos de que BouncyCastle esté disponible en Android
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    // =======================================================
    // ========== PARÁMETROS GLOBALES DE PBKDF2 ==============
    // =======================================================
    private const val PBKDF2_ITERATIONS = 100_000
    private const val KEY_SIZE_BITS = 256 // 256 bits
    private const val SALT_SIZE = 16
    private const val IV_SIZE_GCM = 12  // IV para GCM

    // =======================================================
    // ============== AES GCM + PBKDF2 =======================
    // =======================================================
    fun encryptAES(plainText: String, password: String): String {
        val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
        val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS, "AES")

        val iv = ByteArray(IV_SIZE_GCM).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        val cipherBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        val combined = ByteArray(salt.size + iv.size + cipherBytes.size)
        System.arraycopy(salt, 0, combined, 0, salt.size)
        System.arraycopy(iv, 0, combined, salt.size, iv.size)
        System.arraycopy(cipherBytes, 0, combined, salt.size + iv.size, cipherBytes.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    fun decryptAES(base64Cipher: String, password: String): String {
        val allBytes = Base64.decode(base64Cipher, Base64.NO_WRAP)
        if (allBytes.size < SALT_SIZE + IV_SIZE_GCM) {
            return "Error: datos inválidos para AES."
        }

        val salt = allBytes.copyOfRange(0, SALT_SIZE)
        val iv = allBytes.copyOfRange(SALT_SIZE, SALT_SIZE + IV_SIZE_GCM)
        val cipherBytes = allBytes.copyOfRange(SALT_SIZE + IV_SIZE_GCM, allBytes.size)

        val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS, "AES")

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        val plainBytes = cipher.doFinal(cipherBytes)
        return String(plainBytes, Charsets.UTF_8)
    }

    // =======================================================
    // ============= CAMELLIA GCM (Lightweight) ==============
    // =======================================================
    fun encryptCamellia(plainText: String, password: String): String {
        val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
        val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)
        val iv = ByteArray(IV_SIZE_GCM).also { SecureRandom().nextBytes(it) }

        // Usamos GCMBlockCipher + CamelliaEngine
        val gcm = org.bouncycastle.crypto.modes.GCMBlockCipher(org.bouncycastle.crypto.engines.CamelliaEngine())
        val aeadParams = AEADParameters(KeyParameter(keyBytes), 128, iv)
        gcm.init(true, aeadParams)

        val input = plainText.toByteArray(Charsets.UTF_8)
        val outBuf = ByteArray(gcm.getOutputSize(input.size))
        val len1 = gcm.processBytes(input, 0, input.size, outBuf, 0)
        val len2 = gcm.doFinal(outBuf, len1)
        val cipherBytes = outBuf.copyOfRange(0, len1 + len2)

        val combined = ByteArray(salt.size + iv.size + cipherBytes.size)
        System.arraycopy(salt, 0, combined, 0, salt.size)
        System.arraycopy(iv, 0, combined, salt.size, iv.size)
        System.arraycopy(cipherBytes, 0, combined, salt.size + iv.size, cipherBytes.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    fun decryptCamellia(base64Cipher: String, password: String): String {
        val allBytes = Base64.decode(base64Cipher, Base64.NO_WRAP)
        if (allBytes.size < SALT_SIZE + IV_SIZE_GCM) {
            return "Error: datos inválidos para Camellia."
        }

        val salt = allBytes.copyOfRange(0, SALT_SIZE)
        val iv = allBytes.copyOfRange(SALT_SIZE, SALT_SIZE + IV_SIZE_GCM)
        val cipherData = allBytes.copyOfRange(SALT_SIZE + IV_SIZE_GCM, allBytes.size)

        val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)
        val gcm = org.bouncycastle.crypto.modes.GCMBlockCipher(org.bouncycastle.crypto.engines.CamelliaEngine())
        val aeadParams = AEADParameters(KeyParameter(keyBytes), 128, iv)
        gcm.init(false, aeadParams)

        val outBuf = ByteArray(gcm.getOutputSize(cipherData.size))
        val len1 = gcm.processBytes(cipherData, 0, cipherData.size, outBuf, 0)
        val len2 = gcm.doFinal(outBuf, len1)

        val plainBytes = outBuf.copyOfRange(0, len1 + len2)
        return String(plainBytes, Charsets.UTF_8)
    }

    // =======================================================
    // =========== ChaCha20-Poly1305 (API Cipher) ============
    // =======================================================
    fun encryptChaCha20Poly1305(plainText: String, password: String): String {
        val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
        val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS, "ChaCha20")

        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
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

    fun decryptChaCha20Poly1305(base64Cipher: String, password: String): String {
        val allBytes = Base64.decode(base64Cipher, Base64.NO_WRAP)
        if (allBytes.size < SALT_SIZE + 12) {
            return "Error: datos inválidos para ChaCha20Poly1305."
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
    // ================ DES (ECB/PKCS5) ======================
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

    // =======================================================
    // ========= XChaCha20-Poly1305 (Lightweight) ============
    // =======================================================
    fun encryptXChaCha20Poly1305(plainText: String, password: String): String {
        val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
        val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)

        // Nonce de 24 bytes
        val nonce24 = ByteArray(24).also { SecureRandom().nextBytes(it) }

        // Llamada a XChaCha20Poly1305 (clase hipotética con Lightweight API)
        val aad = ByteArray(0)
        val cipherBytes = XChaCha20Poly1305.encrypt(keyBytes, nonce24, aad, plainText.toByteArray(Charsets.UTF_8))

        val combined = ByteArray(salt.size + nonce24.size + cipherBytes.size)
        System.arraycopy(salt, 0, combined, 0, salt.size)
        System.arraycopy(nonce24, 0, combined, salt.size, nonce24.size)
        System.arraycopy(cipherBytes, 0, combined, salt.size + nonce24.size, cipherBytes.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    fun decryptXChaCha20Poly1305(base64Cipher: String, password: String): String {
        val allBytes = Base64.decode(base64Cipher, Base64.NO_WRAP)
        if (allBytes.size < SALT_SIZE + 24) {
            return "Error: datos inválidos para XChaCha20Poly1305."
        }
        val salt = allBytes.copyOfRange(0, SALT_SIZE)
        val nonce24 = allBytes.copyOfRange(SALT_SIZE, SALT_SIZE + 24)
        val cipherBytes = allBytes.copyOfRange(SALT_SIZE + 24, allBytes.size)

        val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)
        val aad = ByteArray(0)

        return try {
            val plainBytes = XChaCha20Poly1305.decrypt(keyBytes, nonce24, aad, cipherBytes)
            String(plainBytes, Charsets.UTF_8)
        } catch (e: org.bouncycastle.crypto.InvalidCipherTextException) {
            "Error: autenticidad no válida o contraseña incorrecta."
        }
    }

    // =======================================================
    // =============== AEGIS-256 (con tu clase) ==============
    // =======================================================

    /**
     * Cifra con AEGIS-256 usando la clase Aegis256.
     * Estructura final que guardamos en Base64:
     *   SALT(16) + NONCE(32) + (CIPHERTEXT + TAG)
     *
     * Tu clase Aegis256 (Java) pide clave de 32 bytes y nonce de 32 bytes.
     * Tag puede ser 16 o 32, según el constructor.
     */
    fun encryptAegis256(plainText: String, password: String): String {
        // 1) Generar salt
        val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
        // 2) Derivar clave 256 bits
        val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)

        // 3) Nonce de 32 bytes
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }

        // 4) Instanciamos Aegis256 con tag de 16 bytes
        val aegis = Aegis256(keyBytes, nonce, 16)

        // 5) Cifrar => la función Java no admite named arguments, usamos posición
        val ciphertextWithTag = aegis.encrypt(
            plainText.toByteArray(Charsets.UTF_8),
            null  // AD nulo
        )

        // 6) Concatenar salt + nonce + ciphertext+tag
        val combined = ByteArray(salt.size + nonce.size + ciphertextWithTag.size)
        System.arraycopy(salt, 0, combined, 0, salt.size)
        System.arraycopy(nonce, 0, combined, salt.size, nonce.size)
        System.arraycopy(ciphertextWithTag, 0, combined, salt.size + nonce.size, ciphertextWithTag.size)

        // 7) Base64
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    /**
     * Descifra con AEGIS-256:
     *  SALT(16) + NONCE(32) + (CIPHERTEXT+TAG)
     */
    fun decryptAegis256(base64Cipher: String, password: String): String {
        val allBytes = Base64.decode(base64Cipher, Base64.NO_WRAP)
        if (allBytes.size < 64) {
            return "Error: datos insuficientes para AEGIS-256 (min 64 bytes)."
        }

        val salt = allBytes.copyOfRange(0, 16)
        val nonce = allBytes.copyOfRange(16, 48)
        val ciphertextPlusTag = allBytes.copyOfRange(48, allBytes.size)
        if (ciphertextPlusTag.isEmpty()) {
            return "Error: no hay ciphertext en AEGIS-256."
        }

        // Derivar clave
        val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)

        // Instanciamos Aegis256 igual que en encrypt
        val aegis = Aegis256(keyBytes, nonce, 16)

        return try {
            // Llamada a decrypt => sin named arguments
            val plaintextBytes = aegis.decrypt(ciphertextPlusTag, null)
            String(plaintextBytes, Charsets.UTF_8)
        } catch (ex: VerificationFailedException) {
            "Error: Tag inválido o contraseña incorrecta (Aegis256)."
        } catch (ex: Exception) {
            "Error genérico al descifrar Aegis256: ${ex.message}"
        }
    }

    // =======================================================
    // ============== PBKDF2 y Key Derivation ================
    // =======================================================
    private fun deriveKeyPBKDF2(
        password: String,
        salt: ByteArray,
        keySizeBits: Int,
        algorithmForKeySpec: String
    ): SecretKeySpec {
        val keyBytes = deriveKeyBytes(password, salt, keySizeBits)
        return SecretKeySpec(keyBytes, algorithmForKeySpec)
    }

    /**
     * Versión que devuelve solo los bytes,
     * para la Lightweight API y otras clases personalizadas
     */
    fun deriveKeyBytes(password: String, salt: ByteArray, keySizeBits: Int): ByteArray {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(
            password.toCharArray(),
            salt,
            PBKDF2_ITERATIONS,
            keySizeBits
        )
        val tmp = factory.generateSecret(spec)
        return tmp.encoded
    }
}
