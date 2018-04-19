package com.afollestad.androidsecurestorage

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.util.Base64
import com.f2prateek.rx.preferences2.RxSharedPreferences
import io.reactivex.Observable
import io.reactivex.Single
import io.reactivex.functions.Function
import io.reactivex.schedulers.Schedulers
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.UnsupportedEncodingException
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Calendar
import java.util.concurrent.Callable
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.security.auth.x500.X500Principal

class RxSecureStorage(
  private var context: Context,
  private var alias: String
) {
  private lateinit var keyStore: KeyStore
  private var sharedPreferences: RxSharedPreferences

  init {
    context = context.applicationContext
    val prefs = context.getSharedPreferences(
        String.format("%s-%s", context.packageName, alias), Context.MODE_PRIVATE
    )
    this.sharedPreferences = RxSharedPreferences.create(prefs)
  }

  @Throws(Exception::class)
  private fun initIfNecessary() {
    if (::keyStore.isInitialized) {
      return
    }
    try {
      keyStore = KeyStore.getInstance(AndroidKeyStore)
      keyStore.load(null)
      if (!keyStore.containsAlias(alias)) {
        // Generate a key pair for encryption
        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 30)
        val spec = KeyPairGeneratorSpec.Builder(context.applicationContext)
            .setAlias(alias)
            .setSubject(X500Principal("CN=$alias"))
            .setSerialNumber(BigInteger.TEN)
            .setStartDate(start.time)
            .setEndDate(end.time)
            .build()
        val kpg = KeyPairGenerator.getInstance("RSA", AndroidKeyStore)
        kpg.initialize(spec)
        kpg.generateKeyPair()
      }
    } catch (e: Exception) {
      throw Exception("Failed to initialize this RxSecureStorage instance.", e)
    }
  }

  fun encrypt(data: ByteArray): Single<ByteArray> {
    return Single.fromCallable(
        Callable {
          initIfNecessary()

          var outputStream: ByteArrayOutputStream? = null
          var cipherOutputStream: CipherOutputStream? = null
          try {
            val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
            val publicKey = privateKeyEntry.certificate.publicKey

            val input = cipher
            input.init(Cipher.ENCRYPT_MODE, publicKey)

            outputStream = ByteArrayOutputStream()
            cipherOutputStream = CipherOutputStream(outputStream, input)
            cipherOutputStream.write(data)
            cipherOutputStream.closeQuietly()

            return@Callable outputStream.toByteArray()
          } catch (e: Exception) {
            throw Exception("Failed to encrypt data with alias $alias", e)
          } finally {
            cipherOutputStream.closeQuietly()
            outputStream.closeQuietly()
          }
        })
        .observeOn(Schedulers.computation())
  }

  fun encryptString(text: String): Single<String> {
    val textBytes: ByteArray
    try {
      textBytes = text.toByteArray(charset("UTF-8"))
    } catch (e: UnsupportedEncodingException) {
      return Single.error(Exception("Failed convert text to bytes.", e))
    }

    return encrypt(textBytes)
        .map { encryptedData -> Base64.encodeToString(encryptedData, Base64.DEFAULT) }
        .observeOn(Schedulers.computation())
  }

  fun decrypt(encryptedData: ByteArray): Single<ByteArray> {
    return Single.fromCallable(
        Callable {
          initIfNecessary()

          var cipherInputStream: CipherInputStream? = null
          var bos: ByteArrayOutputStream? = null
          try {
            val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
            val privateKey = privateKeyEntry.privateKey

            val output = cipher
            output.init(Cipher.DECRYPT_MODE, privateKey)

            cipherInputStream = CipherInputStream(ByteArrayInputStream(encryptedData), output)
            bos = ByteArrayOutputStream()
            cipherInputStream.copyTo(bos, 512)
            return@Callable bos.toByteArray()
          } catch (e: Exception) {
            throw Exception("Failed to decrypt data with $alias", e)
          } finally {
            cipherInputStream.closeQuietly()
            bos.closeQuietly()
          }
        })
        .observeOn(Schedulers.computation())
  }

  fun decryptString(encryptedText: String?): Single<String> {
    val textBytes = Base64.decode(encryptedText, Base64.DEFAULT)
    return decrypt(textBytes)
        .map { encryptedData -> String(encryptedData, 0, encryptedData.size) }
        .observeOn(Schedulers.computation())
  }

  fun getBytes(name: String): Observable<ByteArray> {
    return sharedPreferences
        .getString(name)
        .asObservable()
        .map { base64Value ->
          val encryptedValue = Base64.decode(base64Value, Base64.DEFAULT)
          decrypt(encryptedValue).blockingGet()
        }
  }

  fun putBytes(
    name: String,
    value: ByteArray?
  ): Single<Boolean> {
    if (value == null) {
      sharedPreferences.getString(name)
          .delete()
      return Single.just(false)
    }
    return encrypt(value)
        .map { encryptedData ->
          val encryptedString = Base64.encodeToString(encryptedData, Base64.DEFAULT)
          sharedPreferences.getString(name)
              .set(encryptedString)
          true
        }
  }

  fun getString(name: String): Observable<String> {
    return sharedPreferences
        .getString(name)
        .asObservable()
        .map {
          if (it.trim { it <= ' ' }.isEmpty()) {
            ""
          } else decryptString(it).blockingGet()
        }
  }

  fun putString(
    name: String,
    value: String?
  ): Single<Boolean> {
    if (value == null) {
      sharedPreferences.getString(name)
          .delete()
      return Single.just(false)
    }
    return encryptString(value)
        .map { encryptedValue ->
          sharedPreferences.getString(name)
              .set(encryptedValue)
          true
        }
  }

  companion object {

    private const val AndroidKeyStore = "AndroidKeyStore"

    fun create(
      context: Context,
      alias: String
    ): RxSecureStorage {
      return RxSecureStorage(context, alias)
    }

    // below android m
    // error in android 6: InvalidKeyException: Need RSA private or public key
    // error in android 5: NoSuchProviderException: Provider not available:
    // AndroidKeyStoreBCWorkaround
    private val cipher: Cipher
      get() {
        try {
          return if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL")
          } else {
            Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidKeyStoreBCWorkaround")
          }
        } catch (exception: Exception) {
          throw RuntimeException("getCipher: Failed to get an instance of Cipher", exception)
        }

      }

    private fun Closeable?.closeQuietly() {
      try {
        this?.closeQuietly()
      } catch (__: Throwable) {
      }
    }
  }
}
