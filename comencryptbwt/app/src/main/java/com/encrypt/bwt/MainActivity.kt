package com.encrypt.bwt

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.encrypt.bwt.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var selectedCipher = "AES"

    // Para pedir permiso de POST_NOTIFICATIONS en Android 13+
    private val requestNotificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted ->
            if (!isGranted) {
                Toast.makeText(
                    this,
                    "Permiso de notificaciones denegado. Podría afectar notificaciones.",
                    Toast.LENGTH_LONG
                ).show()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // 1) Pedimos notificaciones en Android 13+ (opcional)
        checkNotificationPermission()

        // 2) Spinner ciphers
        val cipherTypes = resources.getStringArray(R.array.cipher_types)
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, cipherTypes)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        binding.cipherTypeSpinner.adapter = adapter
        binding.cipherTypeSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                selectedCipher = cipherTypes[position]
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // Botón Encriptar
        binding.encryptButton.setOnClickListener {
            val plainText = binding.plainTextInput.text.toString()
            val secretKey = binding.secretKeyInput.text.toString()
            if (plainText.isBlank() || secretKey.isBlank()) {
                Toast.makeText(this, "Falta texto o clave", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val encryptedText = try {
                when (selectedCipher) {
                    "AES" -> EncryptDecryptHelper.encryptAES(plainText, secretKey)
                    "DES" -> EncryptDecryptHelper.encryptDES(plainText, secretKey)
                    "CAMELLIA" -> EncryptDecryptHelper.encryptCamellia(plainText, secretKey)
                    "CHACHA20POLY1305" -> EncryptDecryptHelper.encryptChaCha20Poly1305(plainText, secretKey)
                    "XCHACHA20POLY1305" -> EncryptDecryptHelper.encryptXChaCha20Poly1305(plainText, secretKey)
                    "AEGIS256" -> EncryptDecryptHelper.encryptAegis256(plainText, secretKey)
                    else -> "Cipher not implemented"
                }
            } catch (e: Exception) {
                e.printStackTrace()
                getString(R.string.encrypt_error_message)
            }
            binding.encryptedTextOutput.setText(encryptedText)
        }

        // Botón Desencriptar
        binding.decryptButton.setOnClickListener {
            val cipherText = binding.encryptedTextInput.text.toString()
            val secretKey = binding.secretKeyInput.text.toString()
            if (cipherText.isBlank() || secretKey.isBlank()) {
                Toast.makeText(this, "Falta texto o clave", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val decryptedText = try {
                when (selectedCipher) {
                    "AES" -> EncryptDecryptHelper.decryptAES(cipherText, secretKey)
                    "DES" -> EncryptDecryptHelper.decryptDES(cipherText, secretKey)
                    "CAMELLIA" -> EncryptDecryptHelper.decryptCamellia(cipherText, secretKey)
                    "CHACHA20POLY1305" -> EncryptDecryptHelper.decryptChaCha20Poly1305(cipherText, secretKey)
                    "XCHACHA20POLY1305" -> EncryptDecryptHelper.decryptXChaCha20Poly1305(cipherText, secretKey)
                    "AEGIS256" -> EncryptDecryptHelper.decryptAegis256(cipherText, secretKey)
                    else -> "Cipher not implemented"
                }
            } catch (e: Exception) {
                e.printStackTrace()
                getString(R.string.decrypt_error_message)
            }
            binding.decryptedTextOutput.setText(decryptedText)
        }

        // Botón Manage Keys
        binding.manageKeysButton.setOnClickListener {
            startActivity(Intent(this, KeyManagerActivity::class.java))
        }

        // Botón Select Key (copiar la clave seleccionada al EditText)
        binding.selectKeyButton.setOnClickListener {
            pickStoredKey()
        }

        // Botón FILE ENCRYPTION
        binding.buttonFileEncryption.setOnClickListener {
            startActivity(Intent(this, FileEncryptionActivity::class.java))
        }

        // Botón "BurbujaEncryption" para (des)activar la lógica del servicio
        binding.buttonBubbleEncryption.setOnClickListener {
            toggleAccessibilityLogic()
        }

        // Botón "Start DialogFlow"
        val btnStartDialogFlow = findViewById<Button>(R.id.buttonStartOverlay)
        btnStartDialogFlow.text = "Start DialogFlow"
        btnStartDialogFlow.setOnClickListener {
            startDialogFlowExample()
        }

        // Ocultamos el botón StopOverlay
        val btnStopOverlay = findViewById<Button>(R.id.buttonStopOverlay)
        btnStopOverlay.visibility = View.GONE
    }

    /**
     * Activa o desactiva la lógica interna del AccessibilityEncryptionService
     * (sin deshabilitarlo en Ajustes).
     */
    private fun toggleAccessibilityLogic() {
        val prefs = getSharedPreferences("AccessibilityPrefs", MODE_PRIVATE)
        val currentlyEnabled = prefs.getBoolean("accessibility_enabled", true)
        val newValue = !currentlyEnabled
        prefs.edit().putBoolean("accessibility_enabled", newValue).apply()

        if (newValue) {
            Toast.makeText(this, "Función de accesibilidad reactivada", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, "Función de accesibilidad desactivada", Toast.LENGTH_SHORT).show()
        }
    }

    private fun checkNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33) {
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                requestNotificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun pickStoredKey() {
        val keyItems = KeysRepository.loadKeys(this)
        if (keyItems.isEmpty()) {
            Toast.makeText(this, "No hay claves guardadas", Toast.LENGTH_SHORT).show()
            return
        }
        val nicknameList = keyItems.map { it.nickname }.toMutableList()
        val addNew = getString(R.string.add_new_key_option)
        nicknameList.add(addNew)

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.choose_key_dialog_title))
            .setItems(nicknameList.toTypedArray()) { _, which ->
                val selectedNick = nicknameList[which]
                if (selectedNick == addNew) {
                    Toast.makeText(this, "Introduce manualmente la clave en el campo", Toast.LENGTH_SHORT).show()
                } else {
                    val item = keyItems.find { it.nickname == selectedNick }
                    if (item != null) {
                        binding.secretKeyInput.setText(item.secret)
                    } else {
                        Toast.makeText(this, "Error: no se encontró la clave", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .show()
    }

    private fun startDialogFlowExample() {
        val i = Intent(this, DialogFlowEncryptionActivity::class.java)
        i.putExtra("EXTRA_SELECTED_TEXT", "Hello from MainActivity!")
        startActivity(i)
    }
}
