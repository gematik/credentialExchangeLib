package de.gematik.security.credentialExchangeLib.crypto.ecdsa

import de.gematik.security.credentialExchangeLib.crypto.Verifier
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

class Ed25519Verifier(override val publicKey: ByteArray) : Verifier {
    init {
        require(publicKey.size == Ed25519CryptoCredentials.publicKeySize) {
            "wrong private keysize - expected ${Ed25519CryptoCredentials.privateKeySize} was ${publicKey.size}"
        }
    }

    val verifier = Ed25519Signer().apply {
        init(false, Ed25519PublicKeyParameters(publicKey, 0))
    }

    override fun verify(content: List<ByteArray>, signature: ByteArray): Boolean {
        return runCatching {
            check(signature.size == 64) { "signature of length 64 bytes required" }
            content.forEach { verifier.update(it, 0, it.size) }
            verifier.verifySignature(signature)
        }.getOrElse { false }
    }

}