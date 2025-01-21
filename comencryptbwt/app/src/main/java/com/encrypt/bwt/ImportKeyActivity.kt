package com.encrypt.bwt

import android.os.Bundle
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

class ImportKeyActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_KEY_SCANNED = "extra_key_scanned"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 1) Recuperar la clave escaneada
        val scannedKey = intent.getStringExtra(EXTRA_KEY_SCANNED).orEmpty()
        if (scannedKey.isEmpty()) {
            // Si no hay nada, simplemente cerrar
            Toast.makeText(this, "No se obtuvo clave del QR", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        // 2) Mostrar AlertDialog para pedir alias
        val editText = EditText(this).apply {
            hint = getString(R.string.label_enter_nickname_for_generated_key)
        }

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.import_key_from_qr))
            .setMessage(getString(R.string.msg_key_scanned_successfully))
            .setView(editText)
            .setPositiveButton(R.string.save_key_button) { _, _ ->
                val nickname = editText.text.toString().trim()
                if (nickname.isNotEmpty()) {
                    val item = KeyItem(nickname, scannedKey)
                    KeysRepository.addKey(this, item)
                    Toast.makeText(this, "Clave importada correctamente", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Nickname vacío, no se guardó la clave", Toast.LENGTH_SHORT).show()
                }
                finish()  // Cerrar ImportKeyActivity y regresar a KeyManagerActivity en el Back Stack
            }
            .setNegativeButton(R.string.cancel_button) { _, _ ->
                finish()
            }
            .setCancelable(false)
            .show()
    }
}
