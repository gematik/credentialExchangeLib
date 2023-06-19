package de.gematik.security.credentialExchangeLib

import com.apicatalog.jsonld.JsonLd
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.jsonld.document.RdfDocument
import de.gematik.security.credentialExchangeLib.crypto.ProofType
import de.gematik.security.credentialExchangeLib.extensions.deepCopy
import de.gematik.security.credentialExchangeLib.extensions.normalize
import de.gematik.security.credentialExchangeLib.extensions.toJsonDocument
import de.gematik.security.credentialExchangeLib.protocols.Credential
import de.gematik.security.credentialExchangeLib.protocols.JsonLdObject
import de.gematik.security.credentialExchangeLib.protocols.LdProof
import de.gematik.security.credentialExchangeLib.protocols.ProofPurpose
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Test
import java.net.URI
import java.util.*
import kotlin.test.assertEquals

class JsonLdTests {

    val date = Date(1684152736408)

    val credential = Credential(
        atContext = Credential.DEFAULT_JSONLD_CONTEXTS + listOf(URI.create("https://w3id.org/vaccination/v1")),
        type = Credential.DEFAULT_JSONLD_TYPES + listOf("VaccinationCertificate"),
        credentialSubject = JsonObject(
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

    val emptyVaccinationCredentialFrame = JsonLdObject(
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
            )
        )
    )

    val credentialFrame = JsonLdObject(
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
                    "@explicit" to JsonPrimitive(true),
                    "type" to JsonArray(
                        listOf(
                            JsonPrimitive("VaccinationEvent")
                        )
                    ),
                    "batchNumber" to JsonObject(mapOf()),
                    "administeringCentre" to JsonObject(mapOf()),
                    "countryOfVaccination" to JsonObject(mapOf()),
                    "recipient" to JsonObject(
                        mapOf(
                            "@explicit" to JsonPrimitive(true),
                            "id" to JsonObject(mapOf()),
                            "type" to JsonArray(
                                listOf(
                                    JsonPrimitive("VaccineRecipient")
                                )
                            )
                        )
                    )
                )
            )
        )
    )

    @Test
    fun clone() {
        val clone = credential.deepCopy()
        assert(clone != credential) // different objects
        assertEquals( // but same content
            clone.credentialSubject!!.get("recipient")!!.jsonObject.get("gender")!!.jsonPrimitive.content,
            credential.credentialSubject!!.get("recipient")!!.jsonObject.get("gender")!!.jsonPrimitive.content
        )
    }

    @Test
    fun frameCredential() {
        val transformedRdf = credential.normalize().trim().replace(Regex("_:c14n[0-9]*"), "<urn:bnid:$0>")
        val inputDocument = JsonDocument.of(JsonLd.fromRdf(RdfDocument.of(transformedRdf.byteInputStream())).get())
        val frameDocument = emptyVaccinationCredentialFrame.toJsonDocument()
        val jsonObject = JsonLd.frame(inputDocument, frameDocument).options(defaultJsonLdOptions).get()
        val framedCredential = Json.decodeFromString<Credential>(jsonObject.toString())
        val framedRdf = framedCredential.normalize().trim().replace(Regex("<urn:bnid:(_:c14n[0-9]*)>"), "$1")
        assertEquals(credential.normalize().trim(), framedRdf)
        println(json.encodeToString(framedCredential))
    }

    @Test
    fun normalize() {
        val ldProof = LdProof(
            type = listOf(ProofType.BbsBlsSignature2020.name),
            created = date,
            proofPurpose = ProofPurpose.ASSERTION_METHOD,
            verificationMethod = URI("did:key:test#test")
        )
        val normalized = ldProof.normalize()
        val expectedNormalized = """
            _:c14n0 <http://purl.org/dc/terms/created> "2023-05-15T12:12:16Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
            _:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .
            _:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
            _:c14n0 <https://w3id.org/security#verificationMethod> <did:key:test#test> .

        """.trimIndent()
        assertEquals(expectedNormalized, normalized)
    }
}