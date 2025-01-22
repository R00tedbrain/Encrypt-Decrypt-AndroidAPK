![Diseño sin título (75)](https://github.com/user-attachments/assets/c2015c6d-5fa4-4134-8860-c29ea4470b3a)

Com.encrypt.bwt 🔐

¡Bienvenido a com.encrypt.bwt! Esta es una aplicación de cifrado y descifrado para Android que te permite:

    Encriptar o desencriptar texto en la propia app usando una clave manual o guardada.
    Seleccionar texto en cualquier app y, mediante el menú de “Procesar texto…” (ACTION_PROCESS_TEXT) o “Compartir” (ACTION_SEND), encriptarlo o desencriptarlo de forma rápida.
    Gestionar (agregar, eliminar) tus claves de forma segura en EncryptedSharedPreferences, eligiendo un apodo para cada clave (no se revela la clave real en la interfaz).
    Elegir la clave guardada directamente en la pantalla principal para no volver a escribirla.

Características 🛠️

    Encriptar / Desencriptar texto con AES o DES.
    Claves guardadas mediante EncryptedSharedPreferences, con un apodo para identificarlas.
    Menú contextual “Procesar texto…” o “Compartir” en otras apps para cifrar/descifrar sin salir de la app original.
    Interfaz sencilla y personalizable.
    Soporte de minSdk=26 y targetSdk=34.
    Multilenguaje (en strings.xml) con soporte para traducciones adicionales.



Cómo instalar 📲

    Clona este repositorio o descárgalo como ZIP.
    Ábrelo en Android Studio.
    Ve al menú Build → Make Project o Sync Project with Gradle Files.
    Ejecuta en un emulador o un dispositivo real (Android 8+).

Cómo usar la aplicación 🤖

    Abrir la app en tu dispositivo.
    En la pantalla principal:
        Elige el algoritmo de cifrado (AES o DES).
        Escribe tu texto en el campo “Text to Encrypt” si vas a encriptar, o en “Encrypted text” si deseas desencriptar.
        Introduce la clave en “Secret Key” (o pulsa Select Stored Key si ya la tienes guardada).
        Pulsa Encrypt o Decrypt según corresponda.
    Gestionar Claves:
        Pulsa Manage Keys.
        En KeyManagerActivity, añade un apodo y la clave real.
        Para eliminar una clave, mantén pulsado el apodo en la lista (long-click).
    Procesar texto en otras apps:
        Selecciona texto en un navegador (Chrome, etc.) o un editor compatible.
        Toca “Procesar texto…” → “Encrypt with Key” / “Decrypt with Key”.
        Aparecerá un AlertDialog pidiendo la clave o permitiendo elegir una guardada, y luego mostrando el resultado.
    Compartir texto en apps como WhatsApp o Telegram:
        Selecciona “Compartir” → “Encrypt Share” / “Decrypt Share” en el menú.
        Se abrirá la lógica de cifrado/descifrado.

Dependencias y librerías ⚙️

    EncryptedSharedPreferences (AndroidX Security)
    Gson (para serializar las claves en JSON)
    BouncyCastle (opcional; ejemplo de cifrado extra)
    Soporte para Jetpack Compose (opcional; si usas vistas tradicionales no es requerido).


Licencia 📜
## Licencia

Este proyecto está licenciado bajo la [Licencia Pública General de GNU versión 3](https://www.gnu.org/licenses/gpl-3.0.es.html). 
Por favor, revisa el archivo [LICENSE](./LICENSE) para obtener más información.

