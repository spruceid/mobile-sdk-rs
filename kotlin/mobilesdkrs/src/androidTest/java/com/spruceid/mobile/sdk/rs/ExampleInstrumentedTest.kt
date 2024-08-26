package com.spruceid.mobile.sdk.rs

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec

import com.spruceid.mobile.sdk.rs.KeyManagerInterface
import com.spruceid.mobile.sdk.rs.Key
import com.spruceid.mobile.sdk.rs.EncryptedPayload
import kotlin.experimental.xor

class MockKeyManager : KeyManagerInterface {
    private val mockKeyStore = mutableMapOf<String, KeyPair>()

    override fun reset(): Boolean {
        mockKeyStore.clear()
        return true
    }

    override fun keyExists(id: Key): Boolean {
        return mockKeyStore.containsKey(id)
    }

    override fun generateSigningKey(id: Key): Boolean {
        // Create a random p256 key pair
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = keyPairGenerator.generateKeyPair()

        mockKeyStore[id] = keyPair
        return true
    }

    override fun getJwk(id: Key): String {
        val keyPair = mockKeyStore[id] ?: return "{}"

        // Create a JWK representation of the public key
        val publicKey = keyPair.public

        // Generate the x value of the first point on the curve
        val x = publicKey.encoded.copyOfRange(27, 59)
        // Generate the y value of the first point on the curve
        val y = publicKey.encoded.copyOfRange(59, 91)

        // Ensure the x and y values are base64 encoded
        val xBase64 = android.util.Base64.encodeToString(x, android.util.Base64.NO_WRAP)
        val yBase64 = android.util.Base64.encodeToString(y, android.util.Base64.NO_WRAP)

        val jwk = """
            {
                "kid": "$id",
                "kty": "EC",
                "crv": "P-256",
                "x": "$xBase64",
                "y": "$yBase64"
            }
        """.trimIndent()

        return jwk

    }

    override fun signPayload(id: Key, payload: ByteArray): ByteArray {
        val keyPair = mockKeyStore[id] ?: return ByteArray(0)
        val privateKey = keyPair.private
        // Simulate signing (in reality, you'd use Signature class with ECDSA)
        return "ECDSASigned:${payload.toString(Charsets.UTF_8)}".toByteArray()
    }

    override fun generateEncryptionKey(id: Key): Boolean {
        return true
    }

    override fun encryptPayload(id: String, payload: ByteArray): EncryptedPayload {
        // Do a basic XOR encryption for demonstration
        // using a random 16 bytes as IV.

        val iv = ByteArray(16)
        val ciphertext = ByteArray(payload.size)

        for (i in payload.indices) {
            ciphertext[i] = (payload[i].xor(iv[i % 16]))
        }

        return EncryptedPayload(ciphertext, iv)
    }

    override fun decryptPayload(id: String, encryptedPayload: EncryptedPayload): ByteArray {
        // Do a basic XOR decryption for demonstration
        val plaintext = ByteArray(encryptedPayload.ciphertext().size)

        for (i in encryptedPayload.ciphertext().indices) {
            plaintext[i] = (encryptedPayload.ciphertext()[i] xor encryptedPayload.iv()[i % 16])
        }

        return plaintext
    }
}

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
@RunWith(AndroidJUnit4::class)
class UniffiInstrumentedTest {
    @Test
    fun testKeyManagerInterface() {
        val keyManager = MockKeyManager()
        val signingKeyId = "signingKey"

        // Test signing key generation and usage
        assert(keyManager.generateSigningKey(signingKeyId))
        assert(keyManager.keyExists(signingKeyId))

        val signedData = keyManager.signPayload(signingKeyId, "Hello, World!".toByteArray())
        assert(String(signedData).startsWith("ECDSASigned:"))

        // Test encryption key generation and usage
        assert(keyManager.generateEncryptionKey(signingKeyId))
        val plaintext = "Secret message".toByteArray()
        val encryptedPayload = keyManager.encryptPayload(signingKeyId, plaintext)
        val ciphertext = String(encryptedPayload.ciphertext())

        // print ciphertext
        println("Ciphertext")
        println(ciphertext)

        val decryptedData = keyManager.decryptPayload(signingKeyId, encryptedPayload)

        println("Decrypted Data")
        println(decryptedData)

        assert(decryptedData.contentEquals(plaintext))

        // Test reset
        assert(keyManager.reset())
        assert(!keyManager.keyExists(signingKeyId))
    }
}
