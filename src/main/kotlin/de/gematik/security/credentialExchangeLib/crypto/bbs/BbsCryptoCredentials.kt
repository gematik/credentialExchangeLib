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
import de.gematik.security.credentialExchangeLib.crypto.CryptoCredentials
import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import io.github.novacrypto.base58.Base58
import java.net.URI
import kotlin.random.Random

data class BbsCryptoCredentials(override val keyPair: KeyPair) : CryptoCredentials {
    companion object{
        val multiCodecId = byteArrayOf(0xeb.toByte(), 0x01)  // varint of 0xeb
        fun createKeyPair() : KeyPair {
            val bbsKeyPair = Bbs.generateBls12381G2Key(Random.nextBytes(32))
            return KeyPair(bbsKeyPair.secretKey, bbsKeyPair.publicKey)
        }
    }
    override val didKey: URI
    override val verKey: String
    override val verificationMethod: URI
    init {
        require(keyPair.publicKey != null)
        require(Bbs.getBls12381G2PublicKeySize() == keyPair.publicKey.size)
        didKey = URI.create("did:key:z${Base58.base58Encode(multiCodecId + keyPair.publicKey)}")
        verKey = Base58.base58Encode(keyPair.publicKey)
        verificationMethod = URI.create("${didKey}#${didKey.toString().drop(8)}")
    }
}
