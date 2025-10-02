package com.betterauth.implementation

import com.betterauth.interfaces.SigningKey
import com.betterauth.interfaces.Verifier
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class Secp256r1Verifier : Verifier {
    override val signatureLength: Int = 88

    override suspend fun verify(
        message: String,
        signature: String,
        publicKey: String,
    ) {
        Security.addProvider(BouncyCastleProvider())

        val publicKeyBytes = Base64Encoder.decode(publicKey).drop(3).toByteArray()
        val rawSignatureBytes = Base64Encoder.decode(signature).drop(2).toByteArray()
        val messageBytes = message.toByteArray(Charsets.UTF_8)

        // Convert raw signature (64 bytes: r || s) to DER format
        val derSignature = rawToDer(rawSignatureBytes)

        val ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
        val point = ecSpec.curve.decodePoint(publicKeyBytes)
        val pubKeySpec = ECPublicKeySpec(point, ecSpec)

        val keyFactory = java.security.KeyFactory.getInstance("ECDSA", "BC")
        val pubKey = keyFactory.generatePublic(pubKeySpec)

        val sig = Signature.getInstance("SHA256withECDSA", "BC")
        sig.initVerify(pubKey)
        sig.update(messageBytes)

        if (!sig.verify(derSignature)) {
            throw IllegalStateException("invalid signature")
        }
    }

    private fun rawToDer(rawSignature: ByteArray): ByteArray {
        // Raw format is r || s (32 bytes each)
        val r = rawSignature.sliceArray(0 until 32)
        val s = rawSignature.sliceArray(32 until 64)

        // Remove leading zeros but keep at least one byte
        fun trimLeadingZeros(bytes: ByteArray): ByteArray {
            var firstNonZero = 0
            while (firstNonZero < bytes.size - 1 && bytes[firstNonZero] == 0.toByte()) {
                firstNonZero++
            }
            return bytes.sliceArray(firstNonZero until bytes.size)
        }

        var rTrimmed = trimLeadingZeros(r)
        var sTrimmed = trimLeadingZeros(s)

        // Add leading zero if high bit is set (to keep it positive in DER)
        if (rTrimmed[0] < 0) {
            rTrimmed = byteArrayOf(0) + rTrimmed
        }
        if (sTrimmed[0] < 0) {
            sTrimmed = byteArrayOf(0) + sTrimmed
        }

        // Build DER: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
        val totalLength = 2 + rTrimmed.size + 2 + sTrimmed.size
        return byteArrayOf(
            0x30,
            totalLength.toByte(),
            0x02,
            rTrimmed.size.toByte(),
        ) + rTrimmed +
            byteArrayOf(
                0x02,
                sTrimmed.size.toByte(),
            ) + sTrimmed
    }
}

class Secp256r1 : SigningKey {
    private var keyPair: KeyPair? = null
    private val verifierInstance = Secp256r1Verifier()

    suspend fun generate() {
        Security.addProvider(BouncyCastleProvider())

        val keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC")
        val ecGenParameterSpec = ECGenParameterSpec("secp256r1")
        keyPairGenerator.initialize(ecGenParameterSpec, SecureRandom())

        keyPair = keyPairGenerator.generateKeyPair()
    }

    override suspend fun sign(message: String): String {
        Security.addProvider(BouncyCastleProvider())

        val messageBytes = message.toByteArray(Charsets.UTF_8)

        val sig = Signature.getInstance("SHA256withECDSA", "BC")
        sig.initSign(keyPair!!.private)
        sig.update(messageBytes)

        val derSignature = sig.sign()

        // Convert DER signature to raw format (r || s, 64 bytes total)
        val rawSignature = derToRaw(derSignature)

        val padded = byteArrayOf(0, 0) + rawSignature
        val base64 = Base64Encoder.encode(padded)

        return "0I${base64.substring(2)}"
    }

    private fun derToRaw(derSignature: ByteArray): ByteArray {
        // DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
        var offset = 0

        // Skip 0x30 and total length
        offset += 2

        // Skip 0x02
        offset += 1

        // Get r length and r value
        val rLength = derSignature[offset].toInt()
        offset += 1
        var r = derSignature.sliceArray(offset until offset + rLength)
        offset += rLength

        // Skip 0x02
        offset += 1

        // Get s length and s value
        val sLength = derSignature[offset].toInt()
        offset += 1
        var s = derSignature.sliceArray(offset until offset + sLength)

        // Remove leading zero bytes if present (added for sign bit in DER)
        if (r.size == 33 && r[0] == 0.toByte()) {
            r = r.sliceArray(1 until r.size)
        }
        if (s.size == 33 && s[0] == 0.toByte()) {
            s = s.sliceArray(1 until s.size)
        }

        // Pad to 32 bytes if needed
        val rPadded = ByteArray(32)
        val sPadded = ByteArray(32)

        System.arraycopy(r, 0, rPadded, 32 - r.size, r.size)
        System.arraycopy(s, 0, sPadded, 32 - s.size, s.size)

        return rPadded + sPadded
    }

    override suspend fun public(): String {
        if (keyPair == null) {
            throw IllegalStateException("keypair not generated")
        }

        val ecPublicKey = keyPair!!.public as org.bouncycastle.jce.interfaces.ECPublicKey
        val q = ecPublicKey.q
        val compressed = q.getEncoded(true)

        val padded = byteArrayOf(0, 0, 0) + compressed
        val base64 = Base64Encoder.encode(padded)

        return "1AAI${base64.substring(4)}"
    }

    override fun verifier(): Verifier = verifierInstance

    override suspend fun verify(
        message: String,
        signature: String,
    ) {
        verifierInstance.verify(message, signature, public())
    }
}
