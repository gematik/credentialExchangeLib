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

package de.gematik.security.credentialExchangeLib.crypto.ecdsa

import de.gematik.security.credentialExchangeLib.crypto.Verifier
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

class Ed25519Verifier(override val publicKey: ByteArray) : Verifier {
    init {
        require(publicKey.size == Ed25519CryptoCredentials.publicKeySize) {
            "wrong private keysize - expected ${Ed25519CryptoCredentials.privateKeySize} was ${publicKey.size}"
        }
    }

    val verifier = Ed25519Signer().apply {
        init(false, Ed25519PublicKeyParameters(publicKey, 0))
    }

    override fun verify(content: List<ByteArray>, signature: ByteArray): Boolean {
        return runCatching {
            check(signature.size == 64) { "signature of length 64 bytes required" }
            content.forEach { verifier.update(it, 0, it.size) }
            verifier.verifySignature(signature)
        }.getOrElse { false }
    }

}