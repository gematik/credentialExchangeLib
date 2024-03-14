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
import bbs.signatures.ProofMessage
import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import de.gematik.security.credentialExchangeLib.crypto.ProofType
import de.gematik.security.credentialExchangeLib.crypto.Proofer
import de.gematik.security.credentialExchangeLib.crypto.Signer
import java.security.GeneralSecurityException

class BbsPlusSigner(override val keyPair: KeyPair) : Signer, Proofer {
    init {
        keyPair.privateKey?.let {
            require(it.size == Bbs.getSecretKeySize()) {
                "wrong private keysize - expected ${Bbs.getSecretKeySize()} was ${it.size}"
            }
        }
        keyPair.publicKey?.let {
            require(it.size == Bbs.getBls12381G2PublicKeySize()) {
                "wrong public keysize - expected ${Bbs.getBls12381G2PublicKeySize()} was ${it.size}"
            }
        }
    }

    override fun sign(content: List<ByteArray>): ByteArray {
        return runCatching {
            check(keyPair.privateKey != null && keyPair.publicKey!=null){"private and public key required to sign content"}
            Bbs.blsSign(keyPair.privateKey, keyPair.publicKey, content.toTypedArray());
        }.onFailure { throw GeneralSecurityException(it.message) }.getOrThrow()
    }

    override fun deriveProof(signature: ByteArray, nonce: ByteArray, content: List<ProofMessage>): ByteArray {
        return runCatching {
            check(keyPair.publicKey!=null){"public key required to derive proof"}
            Bbs.blsCreateProof(keyPair.publicKey, nonce, signature, content.toTypedArray());
        }.onFailure { throw GeneralSecurityException(it.message) }.getOrThrow()
    }

    override val derivedProofType = ProofType.BbsBlsSignatureProof2020
}