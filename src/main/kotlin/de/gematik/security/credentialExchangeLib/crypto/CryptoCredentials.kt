package de.gematik.security.credentialExchangeLib.crypto

import java.net.URI

interface CryptoCredentials {
    val keyPair: KeyPair
    val didKey: URI
    val verKey: String
    val verificationMethod: URI
}