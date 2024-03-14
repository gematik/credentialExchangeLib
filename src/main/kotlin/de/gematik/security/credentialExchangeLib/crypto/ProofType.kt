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

package de.gematik.security.credentialExchangeLib.crypto

enum class ProofType(val id: String, val isProof: Boolean = false) {
    BbsBlsSignature2020("https://w3id.org/security#BbsBlsSignature2020"),
    BbsBlsSignatureProof2020("https://w3id.org/security#BbsBlsSignatureProof2020", true),
    EcdsaSecp256r1Signature2019("https://w3id.org/security#EcdsaSecp256r1Signature2019"),
    Ed25519Signature2018("https://w3id.org/security#Ed25519Signature2018"),
    EcdsaSecp256k1Signature2019("https://w3id.org/security#EcdsaSecp256k1Signature2019"),
    Dilithium2Signature2023("https://w3id.org/security#Dilithium2Signature2023"),
    Dilithium2SdSignature2023("https://w3id.org/security#Dilithium2SdSignature2023"),
    Dilithium2SdSignatureProof2023("https://w3id.org/security#Dilithium2SdSignatureProof2023", true),
    Dilithium3Signature2023("https://w3id.org/security#Dilithium5Signature2023"),
    Dilithium3SdSignature2023("https://w3id.org/security#Dilithium5SdSignature2023"),
    Dilithium3SdSignatureProof2023("https://w3id.org/security#Dilithium5SdSignatureProof2023", true),
    Dilithium5Signature2023("https://w3id.org/security#Dilithium5Signature2023"),
    Dilithium5SdSignature2023("https://w3id.org/security#Dilithium5SdSignature2023"),
    Dilithium5SdSignatureProof2023("https://w3id.org/security#Dilithium5SdSignatureProof2023", true)
}