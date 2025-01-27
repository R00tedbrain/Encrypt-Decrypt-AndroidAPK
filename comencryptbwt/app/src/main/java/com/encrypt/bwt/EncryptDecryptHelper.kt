    // filename: EncryptDecryptHelper.kt
    package com.encrypt.bwt

    import android.util.Base64
    import com.encrypt.bwt.aegis.Aegis256
    import com.encrypt.bwt.aegis.VerificationFailedException
    import org.bouncycastle.crypto.InvalidCipherTextException
    import org.bouncycastle.crypto.modes.GCMBlockCipher
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

    /**
     * Este helper maneja:
     *  - Cifrado/descifrado de TEXTOS con AES, DES, Camellia, ChaCha20, XChaCha20, Aegis256 (String)
     *  - Cifrado/descifrado de ARCHIVOS (ByteArray) con los mismos métodos (funciones 'encryptBytesXxx' y 'decryptBytesXxx')
     */
    object EncryptDecryptHelper {

        init {
            // Registrar BouncyCastle si no está ya presente
            if (Security.getProvider("BC") == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }

        // =======================================================
        // ========== PARÁMETROS GLOBALES DE PBKDF2, etc. ========
        // =======================================================
        private const val PBKDF2_ITERATIONS = 100_000
        private const val KEY_SIZE_BITS = 256  // Clave de 256 bits
        private const val SALT_SIZE = 16       // Salt de 16 bytes
        private const val IV_SIZE_GCM = 12     // IV (nonce) de 12 bytes en AES GCM / Camellia GCM
        // Para XChaCha20 => 24 bytes de nonce
        // Para Aegis256 => 32 bytes de nonce

        // =======================================================
        // ============ AES (GCM) - TEXTO (String) ===============
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
        // ============= CAMELLIA (GCM) - TEXTO (String) =========
        // =======================================================
        fun encryptCamellia(plainText: String, password: String): String {
            val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
            val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)
            val iv = ByteArray(IV_SIZE_GCM).also { SecureRandom().nextBytes(it) }

            val gcm = GCMBlockCipher(org.bouncycastle.crypto.engines.CamelliaEngine())
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
            val gcm = GCMBlockCipher(org.bouncycastle.crypto.engines.CamelliaEngine())
            val aeadParams = AEADParameters(KeyParameter(keyBytes), 128, iv)
            gcm.init(false, aeadParams)

            val outBuf = ByteArray(gcm.getOutputSize(cipherData.size))
            val len1 = gcm.processBytes(cipherData, 0, cipherData.size, outBuf, 0)
            val len2 = gcm.doFinal(outBuf, len1)
            val plainBytes = outBuf.copyOfRange(0, len1 + len2)
            return String(plainBytes, Charsets.UTF_8)
        }

        // =======================================================
        // =========== ChaCha20-Poly1305 (API) - TEXTO ===========
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
        // ================ DES (ECB/PKCS5) - TEXTO ==============
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

        private fun generateDESKey(key: String): SecretKeySpec {
            val keyBytes = key.toByteArray(Charsets.UTF_8).copyOf(8)
            return SecretKeySpec(keyBytes, "DES")
        }

        // =======================================================
        // ========== XChaCha20-Poly1305 (Lightweight) - TEXTO ===
        // =======================================================
        fun encryptXChaCha20Poly1305(plainText: String, password: String): String {
            val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
            val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)

            val nonce24 = ByteArray(24).also { SecureRandom().nextBytes(it) }
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
            } catch (e: InvalidCipherTextException) {
                "Error: autenticidad no válida o contraseña incorrecta."
            }
        }

        // =======================================================
        // =============== AEGIS-256 (Java) - TEXTO ==============
        // =======================================================
        fun encryptAegis256(plainText: String, password: String): String {
            val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
            val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)
            val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }

            val aegis = Aegis256(keyBytes, nonce, 16)
            val cipherTag = aegis.encrypt(plainText.toByteArray(Charsets.UTF_8), null)

            val combined = ByteArray(salt.size + nonce.size + cipherTag.size)
            System.arraycopy(salt, 0, combined, 0, salt.size)
            System.arraycopy(nonce, 0, combined, salt.size, nonce.size)
            System.arraycopy(cipherTag, 0, combined, salt.size + nonce.size, cipherTag.size)
            return Base64.encodeToString(combined, Base64.NO_WRAP)
        }

        fun decryptAegis256(base64Cipher: String, password: String): String {
            val allBytes = Base64.decode(base64Cipher, Base64.NO_WRAP)
            if (allBytes.size < 48) {
                return "Error: datos insuficientes para AEGIS-256 (min 48)."
            }
            val salt = allBytes.copyOfRange(0, 16)
            val nonce = allBytes.copyOfRange(16, 48)
            val cipherTag = allBytes.copyOfRange(48, allBytes.size)

            val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)
            val aegis = Aegis256(keyBytes, nonce, 16)

            return try {
                val plainBytes = aegis.decrypt(cipherTag, null)
                String(plainBytes, Charsets.UTF_8)
            } catch (ex: VerificationFailedException) {
                "Error: Tag inválido o contraseña incorrecta (Aegis256)."
            } catch (ex: Exception) {
                "Error genérico al descifrar Aegis256: ${ex.message}"
            }
        }

        // =======================================================
        // ================ BYTEARRAY (ARCHIVOS) =================
        // =======================================================
        //
        // A continuación, las funciones para cifrar/descifrar
        // archivos en forma de ByteArray, sin Base64,
        // usando la misma lógica de SALT + IV + ciphertext.

        // ==================== AES (ByteArray) ==================
        fun encryptBytesAES(plainData: ByteArray, password: String): ByteArray {
            val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
            val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS, "AES")

            val iv = ByteArray(IV_SIZE_GCM).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

            val cipherBytes = cipher.doFinal(plainData)
            // result => SALT(16) + IV(12) + cipher
            val combined = ByteArray(salt.size + iv.size + cipherBytes.size)
            System.arraycopy(salt, 0, combined, 0, salt.size)
            System.arraycopy(iv, 0, combined, salt.size, iv.size)
            System.arraycopy(cipherBytes, 0, combined, salt.size + iv.size, cipherBytes.size)
            return combined
        }

        fun decryptBytesAES(encryptedData: ByteArray, password: String): ByteArray {
            if (encryptedData.size < SALT_SIZE + IV_SIZE_GCM) {
                throw IllegalArgumentException("Invalid AES data")
            }
            val salt = encryptedData.copyOfRange(0, SALT_SIZE)
            val iv = encryptedData.copyOfRange(SALT_SIZE, SALT_SIZE + IV_SIZE_GCM)
            val cipherBytes = encryptedData.copyOfRange(SALT_SIZE + IV_SIZE_GCM, encryptedData.size)

            val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
            return cipher.doFinal(cipherBytes)
        }

        // ==================== DES (ByteArray) ==================
        // (En esta implementación DES no usa salt+iv.  Solo DES/ECB)
        fun encryptBytesDES(plainData: ByteArray, key: String): ByteArray {
            val secretKey = generateDESKey(key)
            val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return cipher.doFinal(plainData)
        }

        fun decryptBytesDES(encryptedData: ByteArray, key: String): ByteArray {
            val secretKey = generateDESKey(key)
            val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey)
            return cipher.doFinal(encryptedData)
        }

        // ================ Camellia (ByteArray) ================
        fun encryptBytesCamellia(plainData: ByteArray, password: String): ByteArray {
            val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
            val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)
            val iv = ByteArray(IV_SIZE_GCM).also { SecureRandom().nextBytes(it) }

            val gcm = GCMBlockCipher(org.bouncycastle.crypto.engines.CamelliaEngine())
            val aeadParams = AEADParameters(KeyParameter(keyBytes), 128, iv)
            gcm.init(true, aeadParams)

            val output = ByteArray(gcm.getOutputSize(plainData.size))
            val len1 = gcm.processBytes(plainData, 0, plainData.size, output, 0)
            val len2 = gcm.doFinal(output, len1)

            // SALT(16) + IV(12) + ciphertext+tag
            val combined = ByteArray(salt.size + iv.size + (len1 + len2))
            System.arraycopy(salt, 0, combined, 0, salt.size)
            System.arraycopy(iv, 0, combined, salt.size, iv.size)
            System.arraycopy(output, 0, combined, salt.size + iv.size, len1 + len2)
            return combined
        }

        fun decryptBytesCamellia(encryptedData: ByteArray, password: String): ByteArray {
            if (encryptedData.size < SALT_SIZE + IV_SIZE_GCM) {
                throw IllegalArgumentException("Invalid Camellia data")
            }
            val salt = encryptedData.copyOfRange(0, SALT_SIZE)
            val iv = encryptedData.copyOfRange(SALT_SIZE, SALT_SIZE + IV_SIZE_GCM)
            val cipherData = encryptedData.copyOfRange(SALT_SIZE + IV_SIZE_GCM, encryptedData.size)

            val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)
            val gcm = GCMBlockCipher(org.bouncycastle.crypto.engines.CamelliaEngine())
            val aeadParams = AEADParameters(KeyParameter(keyBytes), 128, iv)
            gcm.init(false, aeadParams)

            val output = ByteArray(gcm.getOutputSize(cipherData.size))
            val len1 = gcm.processBytes(cipherData, 0, cipherData.size, output, 0)
            val len2 = gcm.doFinal(output, len1)
            return output.copyOfRange(0, len1 + len2)
        }

        // =========== ChaCha20-Poly1305 (ByteArray) ============
        fun encryptBytesChaCha20(plainData: ByteArray, password: String): ByteArray {
            val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
            val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS, "ChaCha20")

            val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            val spec = GCMParameterSpec(128, nonce)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)

            val cipherBytes = cipher.doFinal(plainData)
            // SALT(16) + NONCE(12) + cipher+tag
            val combined = ByteArray(salt.size + nonce.size + cipherBytes.size)
            System.arraycopy(salt, 0, combined, 0, salt.size)
            System.arraycopy(nonce, 0, combined, salt.size, nonce.size)
            System.arraycopy(cipherBytes, 0, combined, salt.size + nonce.size, cipherBytes.size)
            return combined
        }

        fun decryptBytesChaCha20(encryptedData: ByteArray, password: String): ByteArray {
            if (encryptedData.size < SALT_SIZE + 12) {
                throw IllegalArgumentException("Invalid ChaCha20 data")
            }
            val salt = encryptedData.copyOfRange(0, SALT_SIZE)
            val nonce = encryptedData.copyOfRange(SALT_SIZE, SALT_SIZE + 12)
            val cipherBytes = encryptedData.copyOfRange(SALT_SIZE + 12, encryptedData.size)

            val secretKey = deriveKeyPBKDF2(password, salt, KEY_SIZE_BITS, "ChaCha20")
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            val spec = GCMParameterSpec(128, nonce)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            return cipher.doFinal(cipherBytes)
        }

        // =========== XChaCha20-Poly1305 (ByteArray) ============
        fun encryptBytesXChaCha20(plainData: ByteArray, password: String): ByteArray {
            val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
            val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)

            val nonce24 = ByteArray(24).also { SecureRandom().nextBytes(it) }
            val aad = ByteArray(0)
            val cipherBytes = XChaCha20Poly1305.encrypt(keyBytes, nonce24, aad, plainData)

            // SALT(16) + NONCE(24) + cipher+tag
            val combined = ByteArray(salt.size + nonce24.size + cipherBytes.size)
            System.arraycopy(salt, 0, combined, 0, salt.size)
            System.arraycopy(nonce24, 0, combined, salt.size, nonce24.size)
            System.arraycopy(cipherBytes, 0, combined, salt.size + nonce24.size, cipherBytes.size)
            return combined
        }

        fun decryptBytesXChaCha20(encryptedData: ByteArray, password: String): ByteArray {
            if (encryptedData.size < SALT_SIZE + 24) {
                throw IllegalArgumentException("Invalid XChaCha20 data")
            }
            val salt = encryptedData.copyOfRange(0, SALT_SIZE)
            val nonce24 = encryptedData.copyOfRange(SALT_SIZE, SALT_SIZE + 24)
            val cipherBytes = encryptedData.copyOfRange(SALT_SIZE + 24, encryptedData.size)

            val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)
            val aad = ByteArray(0)
            return XChaCha20Poly1305.decrypt(keyBytes, nonce24, aad, cipherBytes)
        }

        // =============== AEGIS-256 (ByteArray) ================
        fun encryptBytesAegis256(plainData: ByteArray, password: String): ByteArray {
            // SALT(16) + NONCE(32) + ciphertext+tag
            val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }
            val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)

            val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val aegis = Aegis256(keyBytes, nonce, 16)
            val cipherTag = aegis.encrypt(plainData, null)

            val combined = ByteArray(salt.size + nonce.size + cipherTag.size)
            System.arraycopy(salt, 0, combined, 0, salt.size)
            System.arraycopy(nonce, 0, combined, salt.size, nonce.size)
            System.arraycopy(cipherTag, 0, combined, salt.size + nonce.size, cipherTag.size)
            return combined
        }

        fun decryptBytesAegis256(encryptedData: ByteArray, password: String): ByteArray {
            // min 16 + 32 = 48
            if (encryptedData.size < 48) {
                throw IllegalArgumentException("Invalid Aegis256 data (min 48 bytes).")
            }
            val salt = encryptedData.copyOfRange(0, 16)
            val nonce = encryptedData.copyOfRange(16, 48)
            val cipherTag = encryptedData.copyOfRange(48, encryptedData.size)

            val keyBytes = deriveKeyBytes(password, salt, KEY_SIZE_BITS)
            val aegis = Aegis256(keyBytes, nonce, 16)
            return aegis.decrypt(cipherTag, null)
        }

        // =======================================================
        // ============= PBKDF2 y Derivación de Clave ============
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
         * Devuelve solo los bytes de la clave (sin asignar "AES" o "DES" como tal)
         */
        fun deriveKeyBytes(password: String, salt: ByteArray, keySizeBits: Int): ByteArray {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, keySizeBits)
            val tmp = factory.generateSecret(spec)
            return tmp.encoded
        }
    }
