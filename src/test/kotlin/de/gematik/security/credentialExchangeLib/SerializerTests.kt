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

import de.gematik.security.credentialExchangeLib.connection.Invitation
import de.gematik.security.credentialExchangeLib.extensions.toJsonDocument
import de.gematik.security.credentialExchangeLib.extensions.toJsonLdObject
import de.gematik.security.credentialExchangeLib.protocols.*
import de.gematik.security.credentialExchangeLib.serializer.DateSerializer
import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import de.gematik.security.credentialExchangeLib.serializer.UUIDSerializer
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Test
import java.net.URI
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.*
import kotlin.test.assertEquals

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
class SerializerTests {

    val date = ZonedDateTime.of(2023,5,15,12,12,16,0, ZoneId.of("UTC"))
    val presentationDefinitionId = UUID.fromString("250787ea-f892-11ed-b67e-0242ac120002")
    val inputDescriptorId = "3aa55a6e-f892-11ed-b67e-0242ac120002"
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
        issuer = URI.create("did:key:test")
    )

    val presentation = Presentation(
        atContext = Presentation.DEFAULT_JSONLD_CONTEXTS + PresentationSubmission.DEFAULT_JSONLD_CONTEXTS,
        presentationSubmission = PresentationSubmission(
            definitionId = presentationDefinitionId,
            descriptorMap = listOf(
                PresentationSubmission.DescriptorMapEntry(
                    inputDescriptorId,
                    ClaimFormat.LDP_VC,
                    path = "\$.verifiableCredential[0]"
                )
            )
        ),
        verifiableCredential = listOf(credential)
    )

    @Test
    fun serializeURI() {
        val uri = URI("https://example.com")
        val serializedUri = Json.encodeToString(URISerializer, uri)
        assertEquals(uri, Json.decodeFromString(URISerializer, serializedUri))
    }

    @Test
    fun serializeUUID() {
        val uuid = UUID.randomUUID()
        val serializedUUID = Json.encodeToString(UUIDSerializer, uuid)
        assertEquals(uuid, Json.decodeFromString(UUIDSerializer, serializedUUID))
    }

    @Test
    fun serializeDate() {
        val date = Date(0)
        val serializedDate = Json.encodeToString(DateSerializer, date)
        assertEquals("\"1970-01-01T00:00:00Z\"", serializedDate)
        assertEquals(date, Json.decodeFromString(DateSerializer, serializedDate))
    }

    @Test
    fun serializeInvitation() {
        val invitation = Invitation(
            id = UUID.randomUUID().toString(),
            label = "Test Medical Office",
            goal = "Issue Vaccination Certificate",
            goalCode = GoalCode.OFFER_CREDENDIAL,
            from = URI.create("http://example.com")
        )
        val serializedInvitation = json.encodeToString(invitation)
        assertEquals(
            invitation.from,
            json.decodeFromString<Invitation>(serializedInvitation).from)
        println(serializedInvitation)
    }

    @Test
    fun serializeCredentialOffer() {
        val atId = UUID.randomUUID().toString()
        val credentialOffer = CredentialOffer(
            atId,
            outputDescriptor = Descriptor(UUID.randomUUID().toString(), Credential())
        )
        val serializedCredentialOffer = json.encodeToString(credentialOffer)
        assert(
            json.decodeFromString<CredentialOffer>(serializedCredentialOffer).outputDescriptor.frame.credentialSubject == null)
        println(serializedCredentialOffer)
    }

    @Test
    fun serializeCredentialRequest() {
        val atId = UUID.randomUUID().toString()
        val credentialRequest = CredentialRequest(
            atId,
            outputDescriptor = Descriptor(UUID.randomUUID().toString(), Credential()),
            holderKey = URI.create("did:key:holder")
        )
        val serializedCredentialRequest = json.encodeToString(credentialRequest)
        assert(
            json.decodeFromString<CredentialRequest>(serializedCredentialRequest).outputDescriptor.frame.credentialSubject==null)
        println(serializedCredentialRequest)
    }

    @Test
    fun serializeCredentialSubmit() {
        val atId = UUID.randomUUID().toString()
        val credentialSubmit = CredentialSubmit(
            atId,
            credential = credential
        )
        val serializedCredentialSubmit = json.encodeToString(credentialSubmit)
        assertEquals(
            credentialSubmit.credential.issuer,
            json.decodeFromString<CredentialSubmit>(serializedCredentialSubmit).credential.issuer)
        println(serializedCredentialSubmit)
    }

    @Test
    fun serializeJsonLdObject() {
        val jsonLdObject = JsonLdObject(
            content = mapOf(
                "@context" to JsonArray(
                    listOf(
                        JsonPrimitive("https://www.w3.org/2018/credentials/v1"),
                        JsonPrimitive("https://w3id.org/vaccination/v1")
                    )
                ),
                "type" to JsonArray(
                    listOf(
                        JsonPrimitive("VerifiableCredential"),
                        JsonPrimitive("VaccinationCertificate")
                    )
                ),
                "credentialSubject" to JsonObject(
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
                "issuanceDate" to JsonPrimitive("2021-06-23T13:40:12Z"),
                "issuer" to JsonPrimitive("did:key:test")
            )
        )

        val serialized = json.encodeToString(jsonLdObject)
        assertEquals(
            "1626382736",
            json.decodeFromString<JsonLdObject>(serialized).get("credentialSubject")?.jsonObject?.get("batchNumber")?.jsonPrimitive?.content
        )
        println(serialized)
    }

    @Test
    fun unwrappingSingleValueJsonArrays() {
        @Serializable
        data class TestArrays(
            val a: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String>,
            val b: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String>
        )

        val jsonArrays = TestArrays(listOf("a1"), listOf("b1", "b2"))
        val serializedJsonArrays = Json.encodeToString(jsonArrays)
        assertEquals(jsonArrays, Json.decodeFromString(serializedJsonArrays))
        println(json.encodeToString(jsonArrays))
    }

    @Test
    fun serializeLdProof() {
        val ldProof = LdProof(
            atContext = listOf(),
            type = listOf("ProofType.BbsBlsSignature2020.name"),
            creator = URI.create("did:key:test"),
            created = date,
            proofPurpose = ProofPurpose.ASSERTION_METHOD,
            verificationMethod = URI("did:key:test#test")
        )
        val serializedLdProof = Json.encodeToString(ldProof)
        assertEquals(
            ldProof.verificationMethod,
            json.decodeFromString<LdProof>(serializedLdProof).verificationMethod
        )
        println(json.encodeToString(ldProof))
    }

    @Test
    fun serializeCredential() {
        val serializedCredential = json.encodeToString(credential)
        assertEquals(
            "1626382736",
            json.decodeFromString<Credential>(serializedCredential).credentialSubject?.jsonContent?.jsonObject?.get("batchNumber")?.jsonPrimitive?.content
        )
        println(json.encodeToString(credential))
    }

    @Test
    fun credentialToJsonDocument() {
        val jsonDocument = credential.toJsonDocument()
        val expectedJson = """
            {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://w3id.org/vaccination/v1"
                ],
                "type": [
                    "VerifiableCredential",
                    "VaccinationCertificate"
                ],
                "credentialSubject": {
                    "type": "VaccinationEvent",
                    "batchNumber": "1626382736",
                    "dateOfVaccination": "2021-06-23T13:40:12Z",
                    "administeringCentre": "Praxis Sommergarten",
                    "healthProfessional": "883110000015376",
                    "countryOfVaccination": "GE",
                    "nextVaccinationDate": "2021-08-16T13:40:12Z",
                    "order": "3/3",
                    "recipient": {
                        "type": "VaccineRecipient",
                        "givenName": "Marion",
                        "familyName": "Mustermann",
                        "gender": "Female",
                        "birthDate": "1961-08-17"
                    },
                    "vaccine": {
                        "type": "Vaccine",
                        "atcCode": "J07BX03",
                        "medicinalProductName": "COVID-19 Vaccine Moderna",
                        "marketingAuthorizationHolder": "Moderna Biotech"
                    }
                },
                "issuer": "did:key:test",
                "issuanceDate": "2023-05-15T12:12:16Z"
            }
        """.trimIndent()
        assertEquals(expectedJson, json.encodeToString(jsonDocument.toJsonLdObject<Credential>()))
    }

    @Test
    fun serializePresentation() {
        val serializedPresentation = json.encodeToString(presentation)
        assertEquals(
            presentation.presentationSubmission.definitionId,
            Json.decodeFromString<Presentation>(serializedPresentation).presentationSubmission.definitionId
        )
        println(json.encodeToString(presentation))
    }

    @Test
    fun presentationToJsonDocument() {
        val jsonDocument = presentation.toJsonDocument()
        val expectedJson = """
            {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://identity.foundation/presentation-exchange/submission/v1"
                ],
                "type": "VerifiablePresentation",
                "presentationSubmission": {
                    "@context": "https://identity.foundation/presentation-exchange/submission/v1",
                    "type": "PresentationSubmission",
                    "definition_id": "250787ea-f892-11ed-b67e-0242ac120002",
                    "descriptor_map": {
                        "id": "3aa55a6e-f892-11ed-b67e-0242ac120002",
                        "format": "ldp_vc",
                        "path": "${'$'}.verifiableCredential[0]"
                    }
                },
                "verifiableCredential": [
                    {
                        "@context": [
                            "https://www.w3.org/2018/credentials/v1",
                            "https://w3id.org/vaccination/v1"
                        ],
                        "type": [
                            "VerifiableCredential",
                            "VaccinationCertificate"
                        ],
                        "credentialSubject": {
                            "type": "VaccinationEvent",
                            "batchNumber": "1626382736",
                            "dateOfVaccination": "2021-06-23T13:40:12Z",
                            "administeringCentre": "Praxis Sommergarten",
                            "healthProfessional": "883110000015376",
                            "countryOfVaccination": "GE",
                            "nextVaccinationDate": "2021-08-16T13:40:12Z",
                            "order": "3/3",
                            "recipient": {
                                "type": "VaccineRecipient",
                                "givenName": "Marion",
                                "familyName": "Mustermann",
                                "gender": "Female",
                                "birthDate": "1961-08-17"
                            },
                            "vaccine": {
                                "type": "Vaccine",
                                "atcCode": "J07BX03",
                                "medicinalProductName": "COVID-19 Vaccine Moderna",
                                "marketingAuthorizationHolder": "Moderna Biotech"
                            }
                        },
                        "issuer": "did:key:test",
                        "issuanceDate": "2023-05-15T12:12:16Z"
                    }
                ]
            }
        """.trimIndent()
        assertEquals(expectedJson, json.encodeToString(jsonDocument.toJsonLdObject<Presentation>()))
    }
}