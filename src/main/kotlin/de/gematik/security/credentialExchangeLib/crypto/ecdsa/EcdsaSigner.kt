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
import de.gematik.security.credentialExchangeLib.extensions.toByteArray
import org.bouncycastle.crypto.signers.ECDSASigner
import java.security.GeneralSecurityException
import java.security.MessageDigest

abstract class EcdsaSigner(keyPair: KeyPair) : Signer {

    final override val keyPair: KeyPair
    abstract val signer: ECDSASigner

    init {
        keyPair.privateKey?.let {
            require(it.size == EcdsaCryptoCredentials.privateKeySize) {
                "wrong private keysize - expected ${EcdsaCryptoCredentials.privateKeySize} was ${it.size}"
            }
        }
        this.keyPair = keyPair
    }

    override fun sign(content: List<ByteArray>): ByteArray {
        return runCatching {
            check(keyPair.privateKey != null){"private key required to sign content"}
            val hash = MessageDigest.getInstance("SHA-256").apply {
                content.forEach{update(it)}
            }.digest()
            val components = signer.generateSignature(hash);
            components[0].toByteArray(32) + components[1].toByteArray(32)
        }.onFailure { throw GeneralSecurityException(it.message) }.getOrThrow()
    }
}