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

package de.gematik.security.credentialExchangeLib

import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import de.gematik.security.credentialExchangeLib.crypto.ProofType
import de.gematik.security.credentialExchangeLib.crypto.ecdsa.Ed25519CryptoCredentials
import de.gematik.security.credentialExchangeLib.extensions.deepCopy
import de.gematik.security.credentialExchangeLib.extensions.hexToByteArray
import de.gematik.security.credentialExchangeLib.protocols.Credential
import de.gematik.security.credentialExchangeLib.protocols.JsonLdObject
import de.gematik.security.credentialExchangeLib.protocols.LdProof
import de.gematik.security.credentialExchangeLib.protocols.ProofPurpose
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.net.URI
import java.time.ZoneId
import java.time.ZonedDateTime

class Ed25519ProofTest {
    val credentialIssuer = Ed25519CryptoCredentials(
        KeyPair(
            "6fde6ef830a4cb7288760d8c9e43d9ea3fc2d0ff8d19f8d3ec2f06df8dd435d8".hexToByteArray(),
            "c6adf60e9206d5e2763c0167c8fd5e0728e4874aa317d97e797ce971e3bf0578".hexToByteArray()
        )
    )

    val date = ZonedDateTime.of(2023,8,24,13,6,21,408000, ZoneId.of("UTC"))

    val ldProofIssuer = LdProof(
        atContext = listOf(URI("https://www.w3.org/2018/credentials/v1")),
        type = listOf(ProofType.Ed25519Signature2018.name),
        created = date,
        proofPurpose = ProofPurpose.ASSERTION_METHOD,
        verificationMethod = credentialIssuer.verificationMethod
    )

    val credential = Credential(
        atContext = Credential.DEFAULT_JSONLD_CONTEXTS + listOf(URI.create("https://w3id.org/vaccination/v1")),
        type = Credential.DEFAULT_JSONLD_TYPES + listOf("VaccinationCertificate"),
        credentialSubject = JsonLdObject(
            mapOf(
                "type" to JsonPrimitive("VaccinationEvent"),
                "batchNumber" to JsonPrimitive("1626382736"),
                "dateOfVaccination" to JsonPrimitive("2021-06-23T13:40:12Z"),
                "administeringCentre" to JsonPrimitive("Praxis Sommergarten"),
                "healthProfessional" to JsonPrimitive("883110000015376"),
                "countryOfVaccination" to JsonPrimitive("GE"),
                "nextVaccinationDate" to JsonPrimitive("2021-08-16T13:40:12Z"),
                "order" to JsonPrimitive("3/3"),
                "recipient" to JsonObject(
                    mapOf(
                        "type" to JsonPrimitive("VaccineRecipient"),
                        "givenName" to JsonPrimitive("Marion"),
                        "familyName" to JsonPrimitive("Mustermann"),
                        "gender" to JsonPrimitive("Female"),
                        "birthDate" to JsonPrimitive("1961-08-17")
                    )
                ),
                "vaccine" to JsonObject(
                    mapOf(
                        "type" to JsonPrimitive("Vaccine"),
                        "atcCode" to JsonPrimitive("J07BX03"),
                        "medicinalProductName" to JsonPrimitive("COVID-19 Vaccine Moderna"),
                        "marketingAuthorizationHolder" to JsonPrimitive("Moderna Biotech")
                    )
                )
            )
        ),
        issuanceDate = date,
        issuer = credentialIssuer.didKey
    )

    @Test
    fun testEd25519CryptoCredentials() {
        val cryptoCredentials = Ed25519CryptoCredentials(Ed25519CryptoCredentials.createKeyPair())
        assertEquals("did:key:z6Mksppd1t2HLB1qrrG7FZPew5vQ7T45A52JgKwqn8U3FCLo", credentialIssuer.didKey.toString())
        println(credentialIssuer.didKey)
        assertEquals("ENZaRdmqzdXNkMRQZzRp5zNQHsnDkBmwzK2uwrW2KyZR", credentialIssuer.verKey)
        println(credentialIssuer.verKey)
        assertEquals(
            "did:key:z6Mksppd1t2HLB1qrrG7FZPew5vQ7T45A52JgKwqn8U3FCLo#z6Mksppd1t2HLB1qrrG7FZPew5vQ7T45A52JgKwqn8U3FCLo",
            credentialIssuer.verificationMethod.toString()
        )
        println(credentialIssuer.verificationMethod)
    }

    @Test
    fun signVerifyCredential() {
        val signedCredential =
            credential.deepCopy().apply { sign(ldProofIssuer, credentialIssuer.keyPair.privateKey!!) }
        val result = signedCredential.verify()
        assert(result)
        println(json.encodeToString(signedCredential))
    }

}

