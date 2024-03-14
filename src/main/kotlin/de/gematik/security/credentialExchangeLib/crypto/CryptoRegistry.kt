/*
 * Copyright 2021-2024, gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 */

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