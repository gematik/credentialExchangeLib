package de.gematik.security.credentialExchangeLib

import de.gematik.security.credentialExchangeLib.extensions.deepCopy
import de.gematik.security.credentialExchangeLib.extensions.normalize
import de.gematik.security.credentialExchangeLib.types.LdProof
import de.gematik.security.credentialExchangeLib.types.ProofPurpose
import de.gematik.security.mobilewallet.types.Credential
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import java.net.URI
import java.util.*
import kotlin.test.assertEquals

class JsonLdTests {
    @Test
    fun clone(){
        val credential = Credential(
            atContext = listOf(URI.create("https://w3id.org/vaccination/v1")),
            type = listOf("VaccinationCertificate"),
            credentialSubject = JsonObject(
                mapOf(
                    "type" to JsonPrimitive("VaccinationEvent"),
                    "batchNumber" to JsonPrimitive(1626382736),
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
            issuanceDate = Date(),
            issuer = URI.create("did:key:test")
        )
        val clone = credential.deepCopy()
        assert(clone != credential) // different objects
        assertEquals( // but same content
            clone.credentialSubject.get("recipient")!!.jsonObject.get("gender")!!.jsonPrimitive.content,
            credential.credentialSubject.get("recipient")!!.jsonObject.get("gender")!!.jsonPrimitive.content
        )
    }

    @Test
    fun normalize(){
        val ldProof = LdProof(
            atContext = listOf(),
            type = listOf("https://w3id.org/security#BbsBlsSignature2020"),
            creator = URI.create("did:key:test"),
            created = Date(1684152736408),
            proofPurpose = ProofPurpose.ASSERTION_METHOD,
            verificationMethod = URI("did:key:test#test")
        )
        val normalized = ldProof.normalize()
        val expectedNormalized = """
            _:c14n0 <http://purl.org/dc/terms/created> "2023-05-15T12:12:16Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
            _:c14n0 <http://purl.org/dc/terms/creator> <did:key:test> .
            _:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .
            _:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
            _:c14n0 <https://w3id.org/security#verificationMethod> <did:key:test#test> .

        """.trimIndent()
        assertEquals(expectedNormalized, normalized)
    }
}