package de.gematik.security.credentialExchangeLib.crypto.ecdsa

import de.gematik.security.credentialExchangeLib.crypto.Verifier
import org.bouncycastle.crypto.signers.ECDSASigner
import java.math.BigInteger
import java.security.MessageDigest

abstract class EcdsaVerifier(publicKey: ByteArray) : Verifier {

    final override val publicKey: ByteArray
    abstract val verifier: ECDSASigner

    init {
        require(publicKey.size == EcdsaCryptoCredentials.publicKeySize) {
            "wrong private keysize - expected ${EcdsaCryptoCredentials.privateKeySize} was ${publicKey.size}"
        }
        this.publicKey = publicKey
    }

    override fun verify(content: List<ByteArray>, signature: ByteArray): Boolean {
        return runCatching {
            check(signature.size == 64) { "signature of length 64 bytes required" }
            val hash = MessageDigest.getInstance("SHA-256").apply {
                content.forEach { update(it) }
            }.digest()
            verifier.verifySignature(hash, BigInteger(1, signature.copyOfRange(0,32)), BigInteger(1, signature.copyOfRange(32,64)))
        }.getOrElse{false}
    }

}