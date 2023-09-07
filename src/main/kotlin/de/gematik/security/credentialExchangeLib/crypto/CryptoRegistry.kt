package de.gematik.security.credentialExchangeLib.crypto

import de.gematik.security.credentialExchangeLib.crypto.bbs.BbsPlusSigner
import de.gematik.security.credentialExchangeLib.crypto.bbs.BbsPlusVerifier
import de.gematik.security.credentialExchangeLib.crypto.dilithium.Dilithium2SdSigner
import de.gematik.security.credentialExchangeLib.crypto.dilithium.Dilithium2SdVerifier
import de.gematik.security.credentialExchangeLib.crypto.dilithium.Dilithium2Signer
import de.gematik.security.credentialExchangeLib.crypto.dilithium.Dilithium2Verifier
import de.gematik.security.credentialExchangeLib.crypto.ecdsa.*

object CryptoRegistry {

    private val signers = mutableMapOf<ProofType, (KeyPair) -> Signer>(
        ProofType.BbsBlsSignature2020 to { BbsPlusSigner(it) },
        ProofType.EcdsaSecp256r1Signature2019 to { P256Signer(it) },
        ProofType.EcdsaSecp256k1Signature2019 to { P256K1Signer(it) },
        ProofType.Ed25519Signature2018 to { Ed25519Signer(it) },
        ProofType.Dilithium2Signature2023 to { Dilithium2Signer(it) },
        ProofType.Dilithium2SdSignature2023 to { Dilithium2SdSigner(it) }
    )
    private val verifiers = mutableMapOf<ProofType, (ByteArray) -> Verifier>(
        ProofType.BbsBlsSignature2020 to { BbsPlusVerifier(it) },
        ProofType.BbsBlsSignatureProof2020 to { BbsPlusVerifier(it) },
        ProofType.EcdsaSecp256r1Signature2019 to { P256Verifier(it) },
        ProofType.EcdsaSecp256k1Signature2019 to { P256K1Verifier(it) },
        ProofType.Ed25519Signature2018 to { Ed25519Verifier(it) },
        ProofType.Dilithium2Signature2023 to { Dilithium2Verifier(it) },
        ProofType.Dilithium2SdSignature2023 to { Dilithium2SdVerifier(it) },
        ProofType.Dilithium2SdSignatureProof2023 to { Dilithium2SdVerifier(it) }
    )

    fun registerSigner(type: ProofType, initializer: (KeyPair) -> Signer) {
        signers[type] = initializer
    }

    fun unRegisterSigner(type: ProofType) {
        signers.remove(type)
    }

    fun getSigner(type: ProofType, keyPair: KeyPair): Signer? {
        return signers[type]?.invoke(keyPair)
    }

    fun registerVerifier(type: ProofType, initializer: (ByteArray) -> Verifier) {
        verifiers[type] = initializer
    }

    fun unRegisterVerifier(type: ProofType) {
        verifiers.remove(type)
    }

    fun getVerifier(type: ProofType, publicKey: ByteArray): Verifier? {
        return verifiers[type]?.invoke(publicKey)
    }
}