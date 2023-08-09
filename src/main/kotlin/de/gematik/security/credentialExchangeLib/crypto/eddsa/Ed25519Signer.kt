package de.gematik.security.credentialExchangeLib.crypto.ecdsa

import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import de.gematik.security.credentialExchangeLib.crypto.Signer
import de.gematik.security.credentialExchangeLib.extensions.toByteArray
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.MessageDigest

class Ed25519Signer(override val keyPair: KeyPair) : Signer {
    init {
        keyPair.privateKey?.let {
            require(it.size == Ed25519CryptoCredentials.privateKeySize) {
                "wrong private keysize - expected ${Ed25519CryptoCredentials.privateKeySize} was ${it.size}"
            }
        }

    }

    val signer = Ed25519Signer().apply {
        init(true, Ed25519PrivateKeyParameters(keyPair.privateKey, 0))
    }

    override fun sign(content: List<ByteArray>): ByteArray {
        return runCatching {
            check(keyPair.privateKey != null) { "private key required to sign content" }
            content.forEach { signer.update(it, 0, it.size) }
            signer.generateSignature();
        }.onFailure { throw GeneralSecurityException(it.message) }.getOrThrow()
    }

}