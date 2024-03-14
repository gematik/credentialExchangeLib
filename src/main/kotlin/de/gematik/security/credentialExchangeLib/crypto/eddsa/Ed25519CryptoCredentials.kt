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

import de.gematik.security.credentialExchangeLib.crypto.CryptoCredentials
import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import io.github.novacrypto.base58.Base58
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.net.URI
import java.security.SecureRandom


data class Ed25519CryptoCredentials(override val keyPair: KeyPair) : CryptoCredentials {
    companion object {
        val privateKeySize = 32
        val publicKeySize = 32
        val multiCodecId = byteArrayOf(0xed.toByte(), 0x01) // varint of 0xed
        fun createKeyPair() : KeyPair {
            val gen = Ed25519KeyPairGenerator().apply {
                init(Ed25519KeyGenerationParameters(SecureRandom()))
            }
            val keyPair = gen.generateKeyPair()
            (keyPair.private as Ed25519PrivateKeyParameters).encode(ByteArray(32), 0)
            return KeyPair((keyPair.private as Ed25519PrivateKeyParameters).encoded,
                (keyPair.public as Ed25519PublicKeyParameters).encoded
            )
        }
    }

    override val didKey: URI
    override val verKey: String
    override val verificationMethod: URI

    init {
        require(keyPair.privateKey == null || privateKeySize == keyPair.privateKey.size)
        require(keyPair.publicKey != null && publicKeySize == keyPair.publicKey.size)
        didKey = URI.create("did:key:z${Base58.base58Encode(multiCodecId + keyPair.publicKey)}")
        verKey = Base58.base58Encode(keyPair.publicKey)
        verificationMethod = URI.create("${didKey}#${didKey.toString().drop(8)}")
    }
}
