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
import io.github.novacrypto.base58.Base58
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import java.net.URI

class P256K1CryptoCredentials(keyPair: KeyPair) : EcdsaCryptoCredentials(keyPair) {
    companion object {
        val ecDomainParameters = SECNamedCurves.getByName("secp256k1").let { ECDomainParameters(it.curve, it.g, it.n, it.h, it.seed) }
        val multiCodecId = byteArrayOf(0xe7.toByte(), 0x01) // varint of 0xe7
        fun createPublicKey(privateKey: ByteArray) : ByteArray {
            return createPublicKey(privateKey, ecDomainParameters)
        }
    }

    override val didKey: URI
    override val verificationMethod: URI

    init {
        require(keyPair.privateKey == null || privateKeySize == keyPair.privateKey.size)
        didKey = URI.create("did:key:z${Base58.base58Encode(multiCodecId + keyPair.publicKey!!)}")
        verificationMethod = URI.create("${didKey}#${didKey.toString().drop(8)}")
    }
}
