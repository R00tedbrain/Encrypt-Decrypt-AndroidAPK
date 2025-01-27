//Encryptshareactivity
package com.encrypt.bwt

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.EditText
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.documentfile.provider.DocumentFile

class EncryptShareActivity : AppCompatActivity() {

    private var selectedCipher = "AES"
    private var isFile = false
    private var fileUri: Uri? = null
    private var inputText: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Detección:
        // 1) EXTRA_TEXT => texto
        // 2) EXTRA_STREAM => archivo
        val clipText = intent?.getStringExtra(Intent.EXTRA_TEXT)
        val clipUri = intent?.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)

        if (clipText.isNullOrEmpty() && clipUri == null) {
            showFinalDialog("No text or file to encrypt.")
            return
        }

        if (clipUri != null) {
            // Modo archivo
            isFile = true
            fileUri = clipUri
        } else {
            // Modo texto
            isFile = false
            inputText = clipText
        }

        // 1) Preguntar cipher
        askForCipher { cipherChosen ->
            selectedCipher = cipherChosen
            // 2) Pedir key
            askForKey { key ->
                if (isFile) {
                    encryptFile(fileUri!!, key, selectedCipher)
                } else {
                    encryptText(inputText!!, key, selectedCipher)
                }
            }
        }
    }

    private fun askForCipher(onCipherSelected: (String) -> Unit) {
        val ciphers = arrayOf(
            "AES",
            "DES",
            "CAMELLIA",
            "CHACHA20POLY1305",
            "XCHACHA20POLY1305",
            "AEGIS256"
        )
        AlertDialog.Builder(this)
            .setTitle("Choose Cipher")
            .setItems(ciphers) { _, which ->
                onCipherSelected(ciphers[which])
            }
            .show()
    }

    private fun askForKey(onKeyEntered: (String) -> Unit) {
        val keyItems = KeysRepository.loadKeys(this)
        if (keyItems.isEmpty()) {
            askKeyManually(onKeyEntered)
        } else {
            val nicknames = keyItems.map { it.nickname }.toMutableList()
            val addNew = "Enter a new key..."
            nicknames.add(addNew)
            AlertDialog.Builder(this)
                .setTitle("Choose a key")
                .setItems(nicknames.toTypedArray()) { _, which ->
                    val selected = nicknames[which]
                    if (selected == addNew) {
                        askKeyManually(onKeyEntered)
                    } else {
                        val item = keyItems.find { it.nickname == selected }
                        if (item != null) {
                            onKeyEntered(item.secret)
                        } else {
                            askKeyManually(onKeyEntered)
                        }
                    }
                }
                .show()
        }
    }

    private fun askKeyManually(callback: (String) -> Unit) {
        val edit = EditText(this)
        edit.hint = "Enter encryption key"

        AlertDialog.Builder(this)
            .setTitle("Enter Key")
            .setView(edit)
            .setPositiveButton("OK") { _, _ ->
                val key = edit.text.toString().trim()
                if (key.isNotEmpty()) {
                    callback(key)
                } else {
                    showFinalDialog("Empty key.")
                }
            }
            .setNegativeButton("Cancel") { _, _ ->
                finish()
            }
            .show()
    }

    // ----------------------------------------------------
    // Lógica: Encriptar TEXTO
    // ----------------------------------------------------
    private fun encryptText(plainText: String, key: String, cipher: String) {
        val result = try {
            when (cipher) {
                "AES" -> EncryptDecryptHelper.encryptAES(plainText, key)
                "DES" -> EncryptDecryptHelper.encryptDES(plainText, key)
                "CAMELLIA" -> EncryptDecryptHelper.encryptCamellia(plainText, key)
                "CHACHA20POLY1305" -> EncryptDecryptHelper.encryptChaCha20Poly1305(plainText, key)
                "XCHACHA20POLY1305" -> EncryptDecryptHelper.encryptXChaCha20Poly1305(plainText, key)
                "AEGIS256" -> EncryptDecryptHelper.encryptAegis256(plainText, key)
                else -> "Error: cipher not implemented"
            }
        } catch (ex: Exception) {
            ex.printStackTrace()
            "Error encrypting text: ${ex.message}"
        }
        showFinalDialog(result)
    }

    // ----------------------------------------------------
    // Lógica: Encriptar ARCHIVO
    // ----------------------------------------------------
    private fun encryptFile(uri: Uri, key: String, cipher: String) {
        // 1) Leer bytes
        val data = FileHelper.readAllBytesFromUri(this, uri)
        if (data == null) {
            showFinalDialog("Error reading file.")
            return
        }

        // 2) Cifrar
        val encrypted: ByteArray = try {
            when (cipher) {
                "AES" -> EncryptDecryptHelper.encryptBytesAES(data, key)
                "DES" -> EncryptDecryptHelper.encryptBytesDES(data, key)
                "CAMELLIA" -> EncryptDecryptHelper.encryptBytesCamellia(data, key)
                "CHACHA20POLY1305" -> EncryptDecryptHelper.encryptBytesChaCha20(data, key)
                "XCHACHA20POLY1305" -> EncryptDecryptHelper.encryptBytesXChaCha20(data, key)
                "AEGIS256" -> EncryptDecryptHelper.encryptBytesAegis256(data, key)
                else -> {
                    showFinalDialog("Cipher not implemented.")
                    return
                }
            }
        } catch (ex: Exception) {
            ex.printStackTrace()
            showFinalDialog("Error encrypting file: ${ex.message}")
            return
        }

        // 3) Generar nombre final => se añade ".encrypted"
        val originalName = FileHelper.getFilenameFromUri(this, uri) ?: "file"
        val finalName = "$originalName.encrypted"

        // 4) Crear el nuevo archivo en la misma carpeta que el original
        val sourceDoc = DocumentFile.fromSingleUri(this, uri)
        if (sourceDoc == null) {
            showFinalDialog("Error: Could not access original file.")
            return
        }
        val parentDoc = sourceDoc.parentFile
        if (parentDoc == null) {
            showFinalDialog("Error: No parent folder accessible.")
            return
        }
        if (!parentDoc.isDirectory || !parentDoc.canWrite()) {
            showFinalDialog("Cannot write in original folder.")
            return
        }

        // Si existía un archivo con ese nombre, lo borramos
        parentDoc.findFile(finalName)?.delete()

        val mimeType = "application/octet-stream"
        val newFile = parentDoc.createFile(mimeType, finalName)
        if (newFile == null) {
            showFinalDialog("Failed to create output file.")
            return
        }

        // 5) Escribimos los bytes en el nuevo archivo
        val success = FileHelper.writeAllBytesToUri(this, newFile.uri, encrypted)
        if (!success) {
            showFinalDialog("Error writing encrypted file.")
            return
        }

        showFinalDialog("File encrypted successfully.\nSaved to:\n${newFile.uri}")
    }

    private fun showFinalDialog(msg: String) {
        AlertDialog.Builder(this)
            .setTitle("Encrypt Share")
            .setMessage(msg)
            .setPositiveButton("OK") { _, _ -> finish() }
            .setOnDismissListener { finish() }
            .show()
    }

    private fun copyToClipboard(text: String) {
        val cb = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("EncryptedText", text)
        cb.setPrimaryClip(clip)
    }
}
