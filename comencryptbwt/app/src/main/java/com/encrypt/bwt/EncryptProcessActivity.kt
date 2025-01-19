package com.encrypt.bwt

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.EditText
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

class EncryptProcessActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Texto seleccionado en otra app
        val inputText = intent?.getStringExtra(Intent.EXTRA_PROCESS_TEXT).orEmpty()
        if (inputText.isEmpty()) {
            showFinalDialog(getString(R.string.error_no_text_provided))
            return
        }

        // Pedir clave (diccionario + manual)
        askForKey { userKey ->
            // Encriptar
            val encrypted = try {
                EncryptDecryptHelper.encryptAES(inputText, userKey)
            } catch (e: Exception) {
                e.printStackTrace()
                getString(R.string.encrypt_error_message)
            }
            showFinalDialog(encrypted)
        }
    }

    /**
     * Pide al usuario elegir una de las claves guardadas o introducir nueva.
     */
    private fun askForKey(onKeyEntered: (String) -> Unit) {
        val keyItems = KeysRepository.loadKeys(this)
        if (keyItems.isEmpty()) {
            // No hay claves guardadas -> diálogo manual
            askKeyManually { onKeyEntered(it) }
        } else {
            // Mostrar lista de apodos + opción "Introducir nueva..."
            val nicknames = keyItems.map { it.nickname }.toMutableList()
            val addNew = getString(R.string.add_new_key_option)
            nicknames.add(addNew)

            AlertDialog.Builder(this)
                .setTitle(getString(R.string.choose_key_dialog_title))
                .setItems(nicknames.toTypedArray()) { _, which ->
                    val selected = nicknames[which]
                    if (selected == addNew) {
                        // Elegir manual
                        askKeyManually { onKeyEntered(it) }
                    } else {
                        // Buscar la clave real
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

    /**
     * Diálogo manual: Introducir clave al vuelo
     */
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

    /**
     * Muestra el resultado final (encriptado) en un AlertDialog con opción de copiar.
     */
    private fun showFinalDialog(result: String) {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.encrypted_text_title))
            .setMessage(result)
            .setPositiveButton(R.string.copy_button) { _, _ ->
                copyToClipboard(result)
                finish()
            }
            .setOnDismissListener {
                finish()
            }
            .show()
    }

    private fun copyToClipboard(text: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("EncryptedText", text)
        clipboard.setPrimaryClip(clip)
    }
}
