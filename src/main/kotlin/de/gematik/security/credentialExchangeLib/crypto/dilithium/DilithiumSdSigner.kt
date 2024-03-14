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

package de.gematik.security.credentialExchangeLib.crypto.dilithium

import bbs.signatures.ProofMessage
import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import de.gematik.security.credentialExchangeLib.crypto.ProofType
import de.gematik.security.credentialExchangeLib.crypto.Proofer
import de.gematik.security.credentialExchangeLib.crypto.Signer
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.MessageDigest
import kotlin.random.Random

// The DilithiumSd signature uses salted hashes of messages.
// They effectively prevent searches for known hashes of specific messages.
// On the other hand the salt makes the signature unique even for unspecific input documents.
// Due to their uniqueness DilithiumSdSignatures and their derived proofs are linkable.

abstract class DilithiumSdSigner(keyPair: KeyPair, val params: DilithiumParameters) : Signer, Proofer {

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
        val salt = Random.nextBytes(16)
        return runCatching {
            // 1. hash all messages
            val saltedHashes = content.getSaltedHashes(salt)
            // 2. hash all hashes
            val hash = MessageDigest.getInstance("SHA-256").apply {
                saltedHashes.forEach {
                    update(it)
                }
            }.digest()
            // 3. sign hash and generate signature by concatenating salt and hash
            salt + signer.generateSignature(hash)
        }.onFailure { throw GeneralSecurityException(it.message) }.getOrThrow()
    }

    override fun deriveProof(signature: ByteArray, nonce: ByteArray, content: List<ProofMessage>): ByteArray {
        // 1. retrieve salt
        val salt = signature.copyOfRange(0, 16)
        // 1. calculate all salted hashes
        val saltedHashes = content.map { it.message }.getSaltedHashes(salt)
        // 2. construct info block of disclosed messages and salted hashes of suppressed messages
        var infoBlock = ByteArray(0)
        var numberOfRevealedMessages: Short = 0
        content.forEachIndexed { index, proofMessage ->
            if (proofMessage.type == ProofMessage.PROOF_MESSAGE_TYPE_REVEALED) {
                numberOfRevealedMessages++
                return@forEachIndexed
            }
            infoBlock += (ByteBuffer.allocate(Short.SIZE_BYTES).putShort(numberOfRevealedMessages).array() + saltedHashes[index])
            numberOfRevealedMessages = 0
        }
        infoBlock += ByteBuffer.allocate(Short.SIZE_BYTES).putShort(numberOfRevealedMessages).array()
        // 3. construct proof value by concatenating size of info block, info block and original signature
        return ByteBuffer.allocate(Int.SIZE_BYTES).putInt(infoBlock.size).array() +
                infoBlock +
                signature
    }

    override val derivedProofType = ProofType.Dilithium2SdSignatureProof2023

}

class Dilithium2SdSigner(keyPair: KeyPair) : DilithiumSdSigner(keyPair, DilithiumParameters.dilithium2)
class Dilithium2SdAesSigner(keyPair: KeyPair) : DilithiumSdSigner(keyPair, DilithiumParameters.dilithium2_aes)
class Dilithium3SdSigner(keyPair: KeyPair) : DilithiumSdSigner(keyPair, DilithiumParameters.dilithium3)
class Dilithium3SdAesSigner(keyPair: KeyPair) : DilithiumSdSigner(keyPair, DilithiumParameters.dilithium3_aes)
class Dilithium5SdSigner(keyPair: KeyPair) : DilithiumSdSigner(keyPair, DilithiumParameters.dilithium5)
class Dilithium5SdAesSigner(keyPair: KeyPair) : DilithiumSdSigner(keyPair, DilithiumParameters.dilithium5_aes)