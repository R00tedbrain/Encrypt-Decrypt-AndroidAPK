//MainActivity
package com.encrypt.bwt

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.encrypt.bwt.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var selectedCipher = "AES"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // 1) Configurar Spinner de cifrados
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

        // 2) Botón para “Encriptar”
        binding.encryptButton.setOnClickListener {
            val plainText = binding.plainTextInput.text.toString()
            val secretKey = binding.secretKeyInput.text.toString()

            if (plainText.isBlank() || secretKey.isBlank()) {
                Toast.makeText(this, "Falta texto o clave", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val encryptedText = when (selectedCipher) {
                "AES" -> EncryptDecryptHelper.encryptAES(plainText, secretKey)
                "DES" -> EncryptDecryptHelper.encryptDES(plainText, secretKey)
                else -> {
                    Toast.makeText(this, "Cifrado $selectedCipher no implementado", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
            }
            binding.encryptedTextOutput.setText(encryptedText)
        }

        // 3) Botón para “Desencriptar”
        binding.decryptButton.setOnClickListener {
            val cipherText = binding.encryptedTextInput.text.toString()
            val secretKey = binding.secretKeyInput.text.toString()

            if (cipherText.isBlank() || secretKey.isBlank()) {
                Toast.makeText(this, "Falta texto o clave", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val decryptedText = when (selectedCipher) {
                "AES" -> EncryptDecryptHelper.decryptAES(cipherText, secretKey)
                "DES" -> EncryptDecryptHelper.decryptDES(cipherText, secretKey)
                else -> {
                    Toast.makeText(this, "Cifrado $selectedCipher no implementado", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
            }
            binding.decryptedTextOutput.setText(decryptedText)
        }

        // 4) Botón para abrir la pantalla de gestionar claves (KeyManagerActivity)
        binding.manageKeysButton.setOnClickListener {
            startActivity(Intent(this, KeyManagerActivity::class.java))
        }

        // 5) Botón para “Select Stored Key”: mostrará diálogo con la lista de claves
        binding.selectKeyButton.setOnClickListener {
            pickStoredKey()
        }
    }

    /**
     * Muestra un diálogo con la lista de claves guardadas.
     * Si el usuario elige una, se rellena 'secretKeyInput' con esa clave.
     * Además, añadimos la opción “Enter a new key…” para quien desee introducirla manualmente.
     */
    private fun pickStoredKey() {
        val keyItems = KeysRepository.loadKeys(this)
        if (keyItems.isEmpty()) {
            Toast.makeText(this, "No hay claves guardadas", Toast.LENGTH_SHORT).show()
            return
        }

        // Lista de apodos + “Enter a new key…”
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
}
