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
import org.bouncycastle.crypto.signers.ECDSASigner
import java.math.BigInteger
import java.security.MessageDigest

abstract class EcdsaVerifier(publicKey: ByteArray) : Verifier {

    final override val publicKey: ByteArray
    abstract val verifier: ECDSASigner

    init {
        require(publicKey.size == EcdsaCryptoCredentials.publicKeySize) {
            "wrong private keysize - expected ${EcdsaCryptoCredentials.privateKeySize} was ${publicKey.size}"
        }
        this.publicKey = publicKey
    }

    override fun verify(content: List<ByteArray>, signature: ByteArray): Boolean {
        return runCatching {
            check(signature.size == 64) { "signature of length 64 bytes required" }
            val hash = MessageDigest.getInstance("SHA-256").apply {
                content.forEach { update(it) }
            }.digest()
            verifier.verifySignature(hash, BigInteger(1, signature.copyOfRange(0,32)), BigInteger(1, signature.copyOfRange(32,64)))
        }.getOrElse{false}
    }

}