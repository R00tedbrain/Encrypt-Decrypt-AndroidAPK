package com.encrypt.bwt

import android.os.Bundle
import android.view.LayoutInflater
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ListView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

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

        // Eliminar clave con long click
        listView.setOnItemLongClickListener { _, _, position, _ ->
            val nickname = nicknameList[position]
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
            true
        }

        // Botón "Add Key"
        findViewById<Button>(R.id.buttonAddKey).setOnClickListener {
            showAddKeyDialog()
        }
    }

    private fun showAddKeyDialog() {
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_add_key, null)
        val editNickname = dialogView.findViewById<android.widget.EditText>(R.id.editNickname)
        val editSecret = dialogView.findViewById<android.widget.EditText>(R.id.editSecret)

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
}
