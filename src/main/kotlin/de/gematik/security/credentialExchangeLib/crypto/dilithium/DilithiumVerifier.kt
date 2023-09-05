package de.gematik.security.credentialExchangeLib.crypto.dilithium

import de.gematik.security.credentialExchangeLib.crypto.Verifier
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters
import java.math.BigInteger
import java.security.MessageDigest

abstract class DilithiumVerifier(publicKey: ByteArray, val params: DilithiumParameters, val signatureSize: Int) : Verifier {

    final override val publicKey: ByteArray
    val verifier = org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner()

    init {
        val publicKeyParameters = params.getPublicKeyParameters(publicKey)
        verifier.init(
            false, DilithiumPublicKeyParameters(
                params,
                publicKeyParameters.rho,
                publicKeyParameters.t1
            )
        )
        this.publicKey = publicKey
    }

    override fun verify(content: List<ByteArray>, signature: ByteArray): Boolean {
        return runCatching {
            check(signature.size == signatureSize) { "signature of length $signatureSize expected, but was ${signature.size}" }
            val hash = MessageDigest.getInstance("SHA-256").apply {
                content.forEach { update(it) }
            }.digest()
            verifier.verifySignature(
                hash,
                signature
            )
        }.getOrElse { false }
    }

}

class Dilithium2Verifier(publicKey: ByteArray) : DilithiumVerifier(publicKey, DilithiumParameters.dilithium2, 2420)
class Dilithium3Verifier(publicKey: ByteArray) : DilithiumVerifier(publicKey, DilithiumParameters.dilithium3, 3293)
class Dilithium5Verifier(publicKey: ByteArray) : DilithiumVerifier(publicKey, DilithiumParameters.dilithium5, 4595)
