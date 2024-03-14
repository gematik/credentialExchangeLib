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

package de.gematik.security.credentialExchangeLib.crypto.bbs

import bbs.signatures.Bbs
import de.gematik.security.credentialExchangeLib.crypto.ProofType
import de.gematik.security.credentialExchangeLib.crypto.ProofVerifier
import de.gematik.security.credentialExchangeLib.crypto.Verifier
import java.security.GeneralSecurityException

class BbsPlusVerifier(override val publicKey : ByteArray) : Verifier, ProofVerifier {
    init {
        require(publicKey.size == Bbs.getBls12381G2PublicKeySize()) {
            "wrong keysize - expected ${Bbs.getBls12381G2PublicKeySize()} was ${publicKey.size}"
        }
    }

    override fun verify(content : List<ByteArray>, signature: ByteArray) : Boolean {
        return runCatching {
            Bbs.blsVerify(publicKey, signature, content.toTypedArray());
        }.onFailure{throw GeneralSecurityException(it.message) }.getOrThrow()
    }

    override fun verifyProof(content : List<ByteArray>, proof: ByteArray, nonce: ByteArray) : Boolean {
        return runCatching {
            Bbs.blsVerifyProof(publicKey, proof, nonce, content.toTypedArray());
        }.onFailure{throw GeneralSecurityException(it.message) }.getOrThrow()
    }

    override val originalProofType = ProofType.BbsBlsSignature2020
}