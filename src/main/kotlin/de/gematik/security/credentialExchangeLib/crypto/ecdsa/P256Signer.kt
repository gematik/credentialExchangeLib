package de.gematik.security.credentialExchangeLib.crypto.ecdsa

import bbs.signatures.Bbs
import bbs.signatures.ProofMessage
import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import de.gematik.security.credentialExchangeLib.crypto.Signer
import de.gematik.security.credentialExchangeLib.extensions.toByteArray
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.MessageDigest

class P256Signer(override val keyPair: KeyPair) : Signer {
    init {
        keyPair.privateKey?.let {
            require(it.size == P256CryptoCredentials.privateKeySize) {
                "wrong private keysize - expected ${P256CryptoCredentials.privateKeySize} was ${it.size}"
            }
        }

    }
    val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest())).apply {
        init(true, ECPrivateKeyParameters(BigInteger(1, keyPair.privateKey), secp256r1DomainParameters))
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