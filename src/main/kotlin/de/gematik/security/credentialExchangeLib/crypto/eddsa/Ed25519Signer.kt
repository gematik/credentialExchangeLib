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

import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import de.gematik.security.credentialExchangeLib.crypto.Signer
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.GeneralSecurityException

class Ed25519Signer(override val keyPair: KeyPair) : Signer {
    init {
        keyPair.privateKey?.let {
            require(it.size == Ed25519CryptoCredentials.privateKeySize) {
                "wrong private keysize - expected ${Ed25519CryptoCredentials.privateKeySize} was ${it.size}"
            }
        }

    }

    val signer = Ed25519Signer().apply {
        init(true, Ed25519PrivateKeyParameters(keyPair.privateKey, 0))
    }

    override fun sign(content: List<ByteArray>): ByteArray {
        return runCatching {
            check(keyPair.privateKey != null) { "private key required to sign content" }
            content.forEach { signer.update(it, 0, it.size) }
            signer.generateSignature();
        }.onFailure { throw GeneralSecurityException(it.message) }.getOrThrow()
    }

}