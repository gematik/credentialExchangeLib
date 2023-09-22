package de.gematik.security.credentialExchangeLib.crypto.ecdsa

import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import de.gematik.security.credentialExchangeLib.crypto.Signer
import de.gematik.security.credentialExchangeLib.extensions.toByteArray
import org.bouncycastle.crypto.signers.ECDSASigner
import java.security.GeneralSecurityException
import java.security.MessageDigest

abstract class EcdsaSigner(keyPair: KeyPair) : Signer {

    final override val keyPair: KeyPair
    abstract val signer: ECDSASigner

    init {
        keyPair.privateKey?.let {
            require(it.size == EcdsaCryptoCredentials.privateKeySize) {
                "wrong private keysize - expected ${EcdsaCryptoCredentials.privateKeySize} was ${it.size}"
            }
        }
        this.keyPair = keyPair
    }

    override fun sign(content: List<ByteArray>): ByteArray {
        return runCatching {
            check(keyPair.privateKey != null){"private key required to sign content"}
            val hash = MessageDigest.getInstance("SHA-256").apply {
                content.forEach{update(it)}
            }.digest()
            val components = signer.generateSignature(hash);
            components[0].toByteArray(32) + components[1].toByteArray(32)
        }.onFailure { throw GeneralSecurityException(it.message) }.getOrThrow()
    }
}