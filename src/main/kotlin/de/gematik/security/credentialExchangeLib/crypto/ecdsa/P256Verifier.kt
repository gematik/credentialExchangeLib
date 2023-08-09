package de.gematik.security.credentialExchangeLib.crypto.ecdsa

import bbs.signatures.Bbs
import bbs.signatures.ProofMessage
import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import de.gematik.security.credentialExchangeLib.crypto.Signer
import de.gematik.security.credentialExchangeLib.crypto.Verifier
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.MessageDigest

class P256Verifier(override val publicKey: ByteArray) : Verifier {
    init {
        require(publicKey.size == P256CryptoCredentials.publicKeySize) {
            "wrong private keysize - expected ${P256CryptoCredentials.privateKeySize} was ${publicKey.size}"
        }
    }

    val verifier = ECDSASigner(HMacDSAKCalculator(SHA256Digest())).apply {
        init(false, ECPublicKeyParameters(
            secp256r1DomainParameters.curve.decodePoint(publicKey),
            secp256r1DomainParameters))
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