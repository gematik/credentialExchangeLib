package de.gematik.security.credentialExchangeLib.crypto.ecdsa

import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import java.math.BigInteger

class P256Signer(keyPair: KeyPair) : EcdsaSigner(keyPair) {
    override val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest())).apply {
        init(true, ECPrivateKeyParameters(BigInteger(1, keyPair.privateKey), P256CryptoCredentials.ecDomainParameters))
    }
}