package com.encrypt.bwt

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object EncryptDecryptHelper {

    // ========= AES usando GCM + PBKDF2 para derivar la clave ===========

    /**
     * Cifra un texto con AES/GCM/NoPadding.
     * Usamos PBKDF2 (HmacSHA256) para derivar la key desde [password].
     * Guardamos SALT(16) + IV(12) + ciphertext+tag => Base64.
     */
    fun encryptAES(plainText: String, password: String): String {
        // 1) Generar salt aleatorio (16 bytes)
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)

        // 2) Derivar la key (128 bits) con PBKDF2
        val secretKey = deriveKeyPBKDF2(password, salt)

        // 3) Generar IV (nonce) 12 bytes
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)

        // 4) Preparar Cipher AES/GCM
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv) // Tag = 128 bits
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        // 5) Cifrar
        val cipherBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

        // 6) Concatenar: SALT(16) + IV(12) + cipherBytes
        val combined = ByteArray(salt.size + iv.size + cipherBytes.size)
        System.arraycopy(salt, 0, combined, 0, salt.size)
        System.arraycopy(iv, 0, combined, salt.size, iv.size)
        System.arraycopy(cipherBytes, 0, combined, salt.size + iv.size, cipherBytes.size)

        // 7) Devolver en Base64
        return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    /**
     * Descifra con AES/GCM/NoPadding.
     * Espera Base64( SALT(16) + IV(12) + ciphertext+tag ).
     */
    fun decryptAES(base64Cipher: String, password: String): String {
        // 1) Decodificar Base64
        val allBytes = Base64.decode(base64Cipher, Base64.DEFAULT)
        if (allBytes.size < 16 + 12) {
            // Debe haber al menos salt(16) + iv(12)
            return "Error: datos inválidos."
        }

        // 2) Extraer SALT(16)
        val salt = allBytes.copyOfRange(0, 16)

        // 3) Extraer IV(12)
        val iv = allBytes.copyOfRange(16, 16 + 12)

        // 4) El resto es ciphertext+tag
        val cipherBytes = allBytes.copyOfRange(16 + 12, allBytes.size)

        // 5) Derivar key con PBKDF2 (mismo salt)
        val secretKey = deriveKeyPBKDF2(password, salt)

        // 6) Iniciar Cipher para descifrar
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        // 7) Descifrar
        val plainBytes = cipher.doFinal(cipherBytes)
        return String(plainBytes, Charsets.UTF_8)
    }

    /**
     * Deriva una clave AES-128 bits (16 bytes) con PBKDF2(HmacSHA256).
     */
    private fun deriveKeyPBKDF2(password: String, salt: ByteArray): SecretKeySpec {
        // Ajusta iterationCount a gusto (p.ej. 65536, 100000, etc.)
        val iterationCount = 65536
        val keyLength = 128 // bits

        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength)
        val tmp = factory.generateSecret(spec)
        return SecretKeySpec(tmp.encoded, "AES")
    }

    // ==================== DES (ECB/PKCS5) sin cambios ====================
    fun encryptDES(plainText: String, key: String): String {
        val secretKey = generateDESKey(key)
        val cipher = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey)
        val encryptedBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    fun decryptDES(cipherText: String, key: String): String {
        val secretKey = generateDESKey(key)
        val cipher = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding")
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey)
        val decryptedBytes = cipher.doFinal(Base64.decode(cipherText, Base64.DEFAULT))
        return String(decryptedBytes, Charsets.UTF_8)
    }

    private fun generateDESKey(key: String): javax.crypto.SecretKey {
        val keyBytes = key.toByteArray(Charsets.UTF_8).copyOf(8)
        return SecretKeySpec(keyBytes, "DES")
    }
}
