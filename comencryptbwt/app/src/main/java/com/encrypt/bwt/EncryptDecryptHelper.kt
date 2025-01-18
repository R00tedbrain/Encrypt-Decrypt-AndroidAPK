package com.encrypt.bwt

import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

object EncryptDecryptHelper {

    // AES
    fun encryptAES(plainText: String, key: String): String {
        val secretKey = generateAESKey(key)
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedBytes = cipher.doFinal(plainText.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    fun decryptAES(cipherText: String, key: String): String {
        val secretKey = generateAESKey(key)
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        val decryptedBytes = cipher.doFinal(Base64.decode(cipherText, Base64.DEFAULT))
        return String(decryptedBytes)
    }

    private fun generateAESKey(key: String): SecretKey {
        val keyBytes = key.toByteArray(Charsets.UTF_8).copyOf(16)
        return SecretKeySpec(keyBytes, "AES")
    }

    // DES
    fun encryptDES(plainText: String, key: String): String {
        val secretKey = generateDESKey(key)
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedBytes = cipher.doFinal(plainText.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    fun decryptDES(cipherText: String, key: String): String {
        val secretKey = generateDESKey(key)
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        val decryptedBytes = cipher.doFinal(Base64.decode(cipherText, Base64.DEFAULT))
        return String(decryptedBytes)
    }

    private fun generateDESKey(key: String): SecretKey {
        val keyBytes = key.toByteArray(Charsets.UTF_8).copyOf(8)
        return SecretKeySpec(keyBytes, "DES")
    }
}
