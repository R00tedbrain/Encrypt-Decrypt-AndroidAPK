package com.encrypt.bwt

import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import android.util.Base64
import android.view.LayoutInflater
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import java.security.SecureRandom

class KeyManagerActivity : AppCompatActivity() {

    private lateinit var listView: ListView
    private lateinit var adapter: ArrayAdapter<String>
    private val nicknameList = mutableListOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_key_manager)

        listView = findViewById(R.id.listViewKeys)

        val keyItems = KeysRepository.loadKeys(this)
        nicknameList.clear()
        nicknameList.addAll(keyItems.map { it.nickname })

        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, nicknameList)
        listView.adapter = adapter

        // Long-click: exportar QR o eliminar
        listView.setOnItemLongClickListener { _, _, position, _ ->
            val nickname = nicknameList[position]
            val keyItem = keyItems.find { it.nickname == nickname }
            if (keyItem == null) {
                Toast.makeText(this, "Error: clave no encontrada", Toast.LENGTH_SHORT).show()
                return@setOnItemLongClickListener true
            }
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.options_for_key, nickname))
                .setItems(arrayOf(
                    getString(R.string.export_key_as_qr),
                    getString(R.string.delete_key_title)
                )) { dialog, which ->
                    when (which) {
                        0 -> showQrDialog(keyItem)
                        1 -> confirmDeleteKey(nickname, position)
                    }
                    dialog.dismiss()
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
            true
        }

        // Botón "Add Key" manual
        findViewById<Button>(R.id.buttonAddKey).setOnClickListener {
            showAddKeyDialog()
        }

        // Botón "Generate Random Key"
        findViewById<Button>(R.id.buttonGenerateRandom).setOnClickListener {
            generateRandomKey()
        }

        // Botón "Import Key from QR" -> Lanzamos QrScannerActivity (sin esperar result)
        findViewById<Button>(R.id.buttonImportFromQR).setOnClickListener {
            val intent = Intent(this, QrScannerActivity::class.java)
            startActivity(intent)
        }
    }

    override fun onResume() {
        super.onResume()
        // Cada vez que volvemos aquí, recargamos la lista de claves (por si ImportKeyActivity añadió algo)
        val keyItems = KeysRepository.loadKeys(this)
        nicknameList.clear()
        nicknameList.addAll(keyItems.map { it.nickname })
        adapter.notifyDataSetChanged()
    }

    private fun confirmDeleteKey(nickname: String, position: Int) {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.delete_key_title))
            .setMessage(getString(R.string.delete_key_message, nickname))
            .setPositiveButton(R.string.delete_key_positive) { _, _ ->
                KeysRepository.removeKey(this, nickname)
                nicknameList.removeAt(position)
                adapter.notifyDataSetChanged()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showAddKeyDialog() {
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_add_key, null)
        val editNickname = dialogView.findViewById<EditText>(R.id.editNickname)
        val editSecret = dialogView.findViewById<EditText>(R.id.editSecret)

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.add_key_dialog_title))
            .setView(dialogView)
            .setPositiveButton(R.string.save_key_button) { _, _ ->
                val nickname = editNickname.text.toString().trim()
                val secret = editSecret.text.toString().trim()
                if (nickname.isNotEmpty() && secret.isNotEmpty()) {
                    val item = KeyItem(nickname, secret)
                    KeysRepository.addKey(this, item)
                    nicknameList.add(nickname)
                    adapter.notifyDataSetChanged()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun generateRandomKey() {
        val randomBytes = ByteArray(32)
        SecureRandom().nextBytes(randomBytes)
        val base64Key = Base64.encodeToString(randomBytes, Base64.NO_WRAP)

        val editText = EditText(this).apply {
            hint = getString(R.string.label_enter_nickname_for_generated_key)
        }

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.generate_random_key))
            .setMessage(getString(R.string.msg_enter_alias_for_random))
            .setView(editText)
            .setPositiveButton(R.string.ok_button) { _, _ ->
                val nickname = editText.text.toString().trim()
                if (nickname.isNotEmpty()) {
                    val item = KeyItem(nickname, base64Key)
                    KeysRepository.addKey(this, item)
                    nicknameList.add(nickname)
                    adapter.notifyDataSetChanged()
                    Toast.makeText(this, "Random Key generada y guardada", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Nickname vacío, no se guardó la clave", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton(R.string.cancel_button, null)
            .show()
    }

    private fun showQrDialog(keyItem: KeyItem) {
        val qrBitmap: Bitmap = QrUtils.generateQrCode(keyItem.secret, 512, 512)
        val imageView = ImageView(this)
        imageView.setImageBitmap(qrBitmap)

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.export_key_as_qr))
            .setMessage(getString(R.string.key_alias, keyItem.nickname))
            .setView(imageView)
            .setPositiveButton(R.string.ok_button, null)
            .show()
    }
}
