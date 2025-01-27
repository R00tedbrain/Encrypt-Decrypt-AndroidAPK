// filename: DecryptShareActivity.kt
package com.encrypt.bwt

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.EditText
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

class DecryptShareActivity : AppCompatActivity() {

    private var selectedCipher: String = "AES"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Texto compartido
        val inputText = intent?.getStringExtra(Intent.EXTRA_TEXT).orEmpty()
        if (inputText.isEmpty()) {
            showFinalDialog(getString(R.string.error_no_text_provided))
            return
        }

        // 1) Elegir tipo de cifrado
        askForCipher { cipherChosen ->
            selectedCipher = cipherChosen

            // 2) Luego pedimos la clave
            askForKey { key ->
                val decryptedText = try {
                    when (selectedCipher) {
                        "AES" -> EncryptDecryptHelper.decryptAES(inputText, key)
                        "DES" -> EncryptDecryptHelper.decryptDES(inputText, key)
                        "CAMELLIA" -> EncryptDecryptHelper.decryptCamellia(inputText, key)
                        "CHACHA20POLY1305" -> EncryptDecryptHelper.decryptChaCha20Poly1305(inputText, key)
                        "XCHACHA20POLY1305" -> EncryptDecryptHelper.decryptXChaCha20Poly1305(inputText, key)
                        "AEGIS256" -> EncryptDecryptHelper.decryptAegis256(inputText, key)
                        else -> getString(R.string.decrypt_error_message)
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                    getString(R.string.decrypt_error_message)
                }
                showFinalDialog(decryptedText)
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
            .setTitle(getString(R.string.choose_key_dialog_title))
            .setItems(ciphers) { _, which ->
                onCipherSelected(ciphers[which])
            }
            .show()
    }

    private fun askForKey(onKeyEntered: (String) -> Unit) {
        val keyItems = KeysRepository.loadKeys(this)
        if (keyItems.isEmpty()) {
            askKeyManually { onKeyEntered(it) }
        } else {
            val nicknames = keyItems.map { it.nickname }.toMutableList()
            val addNew = getString(R.string.add_new_key_option)
            nicknames.add(addNew)

            AlertDialog.Builder(this)
                .setTitle(getString(R.string.choose_key_dialog_title))
                .setItems(nicknames.toTypedArray()) { _, which ->
                    val selected = nicknames[which]
                    if (selected == addNew) {
                        askKeyManually { onKeyEntered(it) }
                    } else {
                        val item = keyItems.find { it.nickname == selected }
                        if (item != null) {
                            onKeyEntered(item.secret)
                        } else {
                            askKeyManually { onKeyEntered(it) }
                        }
                    }
                }
                .show()
        }
    }

    private fun askKeyManually(callback: (String) -> Unit) {
        val keyInput = EditText(this).apply {
            hint = getString(R.string.hint_enter_key)
        }

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.enter_key_dialog_title))
            .setView(keyInput)
            .setPositiveButton(R.string.ok_button) { _, _ ->
                val userKey = keyInput.text.toString().trim()
                if (userKey.isNotEmpty()) {
                    callback(userKey)
                } else {
                    showFinalDialog(getString(R.string.error_empty_key))
                }
            }
            .setNegativeButton(R.string.cancel_button) { _, _ -> finish() }
            .setCancelable(false)
            .show()
    }

    private fun showFinalDialog(resultText: String) {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.decrypted_text_title))
            .setMessage(resultText)
            .setPositiveButton(R.string.copy_button) { _, _ ->
                copyToClipboard(resultText)
                finish()
            }
            .setOnDismissListener {
                finish()
            }
            .show()
    }

    private fun copyToClipboard(text: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("DecryptedText", text)
        clipboard.setPrimaryClip(clip)
    }
}
