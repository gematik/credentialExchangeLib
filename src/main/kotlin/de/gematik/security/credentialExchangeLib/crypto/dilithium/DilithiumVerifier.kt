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

import de.gematik.security.credentialExchangeLib.crypto.Verifier
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters
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
class Dilithium2AesVerifier(publicKey: ByteArray) : DilithiumVerifier(publicKey, DilithiumParameters.dilithium2_aes, 2420)
class Dilithium3Verifier(publicKey: ByteArray) : DilithiumVerifier(publicKey, DilithiumParameters.dilithium3, 3293)
class Dilithium3AesVerifier(publicKey: ByteArray) : DilithiumVerifier(publicKey, DilithiumParameters.dilithium3_aes, 3293)
class Dilithium5Verifier(publicKey: ByteArray) : DilithiumVerifier(publicKey, DilithiumParameters.dilithium5, 4595)
class Dilithium5AesVerifier(publicKey: ByteArray) : DilithiumVerifier(publicKey, DilithiumParameters.dilithium5_aes, 4595)
