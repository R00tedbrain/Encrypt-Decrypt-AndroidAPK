package com.encrypt.bwt

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.google.zxing.integration.android.IntentIntegrator

class QrScannerActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val integrator = IntentIntegrator(this)
        integrator.setOrientationLocked(false)
        integrator.setPrompt(getString(R.string.scan_qr_hint))
        integrator.initiateScan()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null) {
            if (result.contents == null) {
                // Usuario canceló -> Simplemente cerrar
                finish()
            } else {
                // Tenemos un QR
                val scannedKey = result.contents

                // Lanzar ImportKeyActivity para guardar la clave
                val intent = Intent(this, ImportKeyActivity::class.java)
                intent.putExtra(ImportKeyActivity.EXTRA_KEY_SCANNED, scannedKey)
                startActivity(intent)

                // Cerrar QrScannerActivity
                finish()
            }
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }
}
