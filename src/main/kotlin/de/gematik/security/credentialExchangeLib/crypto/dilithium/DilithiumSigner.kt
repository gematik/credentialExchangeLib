package de.gematik.security.credentialExchangeLib.crypto.dilithium

import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import de.gematik.security.credentialExchangeLib.crypto.Signer
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters
import java.security.GeneralSecurityException
import java.security.MessageDigest

abstract class DilithiumSigner(keyPair: KeyPair, val params: DilithiumParameters) : Signer {

    final override val keyPair: KeyPair
    val signer = org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner()

    init {
        keyPair.privateKey?.let {
            val privateKeyParameters = params.getPrivateKeyParameters(it)
            signer.init(
                true, DilithiumPrivateKeyParameters(
                    params,
                    privateKeyParameters.rho,
                    privateKeyParameters.k,
                    privateKeyParameters.tr,
                    privateKeyParameters.s1,
                    privateKeyParameters.s2,
                    privateKeyParameters.t0,
                    null
                )
            )
        }
        this.keyPair = keyPair
    }

    override fun sign(content: List<ByteArray>): ByteArray {
        return runCatching {
            val hash = MessageDigest.getInstance("SHA-256").apply {
                content.forEach { update(it) }
            }.digest()
            signer.generateSignature(hash);
        }.onFailure { throw GeneralSecurityException(it.message) }.getOrThrow()
    }
}

class Dilithium2Signer(keyPair: KeyPair) : DilithiumSigner(keyPair, DilithiumParameters.dilithium2)
class Dilithium2AesSigner(keyPair: KeyPair) : DilithiumSigner(keyPair, DilithiumParameters.dilithium2_aes)
class Dilithium3Signer(keyPair: KeyPair) : DilithiumSigner(keyPair, DilithiumParameters.dilithium3)
class Dilithium3AesSigner(keyPair: KeyPair) : DilithiumSigner(keyPair, DilithiumParameters.dilithium3_aes)
class Dilithium5Signer(keyPair: KeyPair) : DilithiumSigner(keyPair, DilithiumParameters.dilithium5)
class Dilithium5AesSigner(keyPair: KeyPair) : DilithiumSigner(keyPair, DilithiumParameters.dilithium5_aes)