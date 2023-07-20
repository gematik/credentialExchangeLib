package de.gematik.security.credentialExchangeLib

import com.apicatalog.jsonld.JsonLd
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.jsonld.document.RdfDocument
import de.gematik.security.credentialExchangeLib.credentialSubjects.*
import de.gematik.security.credentialExchangeLib.crypto.ProofType
import de.gematik.security.credentialExchangeLib.extensions.*
import de.gematik.security.credentialExchangeLib.protocols.Credential
import de.gematik.security.credentialExchangeLib.protocols.JsonLdObject
import de.gematik.security.credentialExchangeLib.protocols.LdProof
import de.gematik.security.credentialExchangeLib.protocols.ProofPurpose
import io.ktor.util.reflect.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Test
import java.net.URI
import java.util.*
import kotlin.test.assertEquals

class JsonLdTests {

    val date = Date(1684152736408)
    val recipientId =
        "did:key:zUC7CgahEtPMHR2JsTnFSbhjFE6bYAm5i2vbFWRUdSUNc45zFAg3rCA6UVoYcDzU5DHAk1HuLV5tgcd6edL8mKLoDRhbz7qzav5yzkDWWgZMh8wTieyjcXtoTSmxNq96nWUgP5V"

    val issuer =
        "did:key:zUC78bhyjquwftxL92uP5xdUA7D7rtNQ43LZjvymncP2KTXtQud1g9JH4LYqoXZ6fyiuDJ2PdkNU9j6cuK1dsGjFB2tEMvTnnHP7iZJomBmmY1xsxBqbPsCMtH6YmjP4ocfGLwv"

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
                        "id" to JsonPrimitive(recipientId),
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
        issuer = URI.create(issuer),
        proof = listOf(
            LdProof(
                type = listOf(ProofType.BbsBlsSignature2020.name),
                created = date,
                proofPurpose = ProofPurpose.ASSERTION_METHOD,
                verificationMethod = URI.create("$issuer#${issuer.drop(8)}"),
                proofValue = "p/YiIfAicLzDd460F516bj9jyoXImWth2RU3ULV4XAXSil91r0c0AzKk6aw+/52GCkOTp3jVKvE0GwQGTFILDVY5qD8/G2qkwELmQwmxKDsD5MNMmJtH57m460w4JcztzLbTbXozTx9ZGtuXdv3UhQ=="
            )
        )
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

    @Test
    fun frameCredential() {
        val credentialWithoutProof = credential.deepCopy().apply { proof = null }
        val transformedRdf = credentialWithoutProof.normalize().trim().replace(Regex("_:c14n[0-9]*"), "<urn:bnid:$0>")
        val inputDocument = JsonDocument.of(JsonLd.fromRdf(RdfDocument.of(transformedRdf.byteInputStream())).get())
        val frameDocument = emptyVaccinationCredentialFrame.toJsonDocument()
        val jsonObject = JsonLd.frame(inputDocument, frameDocument).options(defaultJsonLdOptions).get()
        val framedCredential = Json.decodeFromString<Credential>(jsonObject.toString())
        val framedRdf = framedCredential.normalize().trim().replace(Regex("<urn:bnid:(_:c14n[0-9]*)>"), "$1")
        assertEquals(credentialWithoutProof.normalize().trim(), framedRdf)
        println(json.encodeToString(framedCredential))
    }

    @Test
    fun frameCredentialSelectiv() {
        val credentialWithoutProof = credential.deepCopy().apply { proof = null }
        val transformedRdf = credentialWithoutProof.normalize().trim().replace(Regex("_:c14n[0-9]*"), "<urn:bnid:$0>")
        val inputDocument = JsonDocument.of(JsonLd.fromRdf(RdfDocument.of(transformedRdf.byteInputStream())).get())
        val frameDocument = credentialFrame.toJsonDocument()
        val jsonObject = JsonLd.frame(inputDocument, frameDocument).options(defaultJsonLdOptions).get()
        val framedCredential = Json.decodeFromString<Credential>(jsonObject.toString())
        val framedRdf = framedCredential.normalize().trim().replace(Regex("<urn:bnid:(_:c14n[0-9]*)>"), "$1")
        val expectedFramedRdf = """
            <did:key:zUC7CgahEtPMHR2JsTnFSbhjFE6bYAm5i2vbFWRUdSUNc45zFAg3rCA6UVoYcDzU5DHAk1HuLV5tgcd6edL8mKLoDRhbz7qzav5yzkDWWgZMh8wTieyjcXtoTSmxNq96nWUgP5V> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/vaccination#VaccineRecipient> .
            _:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/vaccination#VaccinationEvent> .
            _:c14n0 <https://w3id.org/vaccination#administeringCentre> "Praxis Sommergarten" .
            _:c14n0 <https://w3id.org/vaccination#batchNumber> "1626382736" .
            _:c14n0 <https://w3id.org/vaccination#countryOfVaccination> "GE" .
            _:c14n0 <https://w3id.org/vaccination#recipient> <did:key:zUC7CgahEtPMHR2JsTnFSbhjFE6bYAm5i2vbFWRUdSUNc45zFAg3rCA6UVoYcDzU5DHAk1HuLV5tgcd6edL8mKLoDRhbz7qzav5yzkDWWgZMh8wTieyjcXtoTSmxNq96nWUgP5V> .
            _:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/vaccination#VaccinationCertificate> .
            _:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
            _:c14n2 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n0 .
            _:c14n2 <https://www.w3.org/2018/credentials#issuanceDate> "2023-05-15T12:12:16Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
            _:c14n2 <https://www.w3.org/2018/credentials#issuer> <did:key:zUC78bhyjquwftxL92uP5xdUA7D7rtNQ43LZjvymncP2KTXtQud1g9JH4LYqoXZ6fyiuDJ2PdkNU9j6cuK1dsGjFB2tEMvTnnHP7iZJomBmmY1xsxBqbPsCMtH6YmjP4ocfGLwv> .
        """.trimIndent()
        assertEquals(expectedFramedRdf, framedRdf)
        println(json.encodeToString(framedCredential))
    }

    @Test
    fun expandCredential() {
        val expandedCredential = JsonLd.expand(credential.toJsonDocument()).options(defaultJsonLdOptions) .get()
        println(json.encodeToString(json.parseToJsonElement(expandedCredential.toString())))
    }

    @Test
    fun compactCredential() {
        val inputDocument = credential.toJsonDocument()
        val context = Credential(
            atContext = credential.atContext + credential.proof!!.get(0).atContext,
            type = credential.type + credential.proof!!.get(0).type!!
        ).toJsonDocument()
        val compactedCredential = JsonLd.compact(inputDocument, context).options(defaultJsonLdOptions).get()
        println(json.encodeToString(json.parseToJsonElement(compactedCredential.toString())))
    }

    @Test
    fun frameCredentialSelectiveWithProof() {
        val inputDocument = credential.toJsonDocument()
        val frame = JsonLdObject(
            content = mapOf(
                "@context" to JsonArray(
                    listOf(
                        JsonPrimitive("https://www.w3.org/2018/credentials/v1"),
                        JsonPrimitive("https://w3id.org/vaccination/v1"),
                        JsonPrimitive("https://w3id.org/security/bbs/v1")
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
                        "@requireAll" to JsonPrimitive(true),
                        "type" to JsonArray(
                            listOf(
                                JsonPrimitive("VaccinationEvent")
                            )
                        ),
                        "order" to JsonObject(mapOf()),
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
                ),
                "proof" to JsonObject(
                    mapOf(
                        "@explicit" to JsonPrimitive(true),
                        "type" to JsonArray(
                            listOf(
                                JsonPrimitive("BbsBlsSignature2020")
                            )
                        ),
                        "proofValue" to JsonObject(mapOf())
                    )
                )
            )
        ).toJsonDocument()
        val framedCredential = JsonLd.frame(inputDocument, frame).options(defaultJsonLdOptions).get()
        println(json.encodeToString(json.parseToJsonElement(framedCredential.toString())))
    }

    @Test
    fun frameCredentialValueNoMatch() {
        val inputDocument = credential.toJsonDocument()
        val frame = JsonLdObject(
            content = mapOf(
                "@context" to JsonArray(
                    listOf(
                        JsonPrimitive("https://www.w3.org/2018/credentials/v1"),
                        JsonPrimitive("https://w3id.org/vaccination/v1"),
                        JsonPrimitive("https://w3id.org/security/bbs/v1")
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
                        "@requireAll" to JsonPrimitive(true),
                        "type" to JsonArray(
                            listOf(
                                JsonPrimitive("VaccinationEvent")
                            )
                        ),
                        "order" to JsonArray(listOf(JsonPrimitive("2/3"))),
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
                ),
                "proof" to JsonObject(mapOf())
            )
        ).toJsonDocument()
        val framedCredential = JsonLd.frame(inputDocument, frame).options(defaultJsonLdOptions).get()
        println(json.encodeToString(json.parseToJsonElement(framedCredential.toString())))
    }

    @Test
    fun frameCredentialValueMatch() {
        val inputDocument = credential.toJsonDocument()
        val frame = JsonLdObject(
            content = mapOf(
                "@context" to JsonArray(
                    listOf(
                        JsonPrimitive("https://www.w3.org/2018/credentials/v1"),
                        JsonPrimitive("https://w3id.org/vaccination/v1"),
                        JsonPrimitive("https://w3id.org/security/bbs/v1")
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
                        "@requireAll" to JsonPrimitive(true),
                        "type" to JsonArray(
                            listOf(
                                JsonPrimitive("VaccinationEvent")
                            )
                        ),
                        "order" to JsonArray(listOf(JsonPrimitive("3/3"))),
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
                ),
                "proof" to JsonObject(mapOf())
            )
        ).toJsonDocument()
        val framedCredential = JsonLd.frame(inputDocument, frame).options(defaultJsonLdOptions).get()
        println(json.encodeToString(json.parseToJsonElement(framedCredential.toString())))
    }

    val vsdCredential = Credential(
        atContext = Credential.DEFAULT_JSONLD_CONTEXTS + listOf(URI.create("https://gematik.de/vsd/v1")),
        type = Credential.DEFAULT_JSONLD_TYPES + listOf("InsuranceCertificate"),
        credentialSubject = json.encodeToJsonElement(
            Insurance(
                insurant = Insurant(
                    insurantId = "X110403565",
                    familyName = "Schühmann",
                    nameExtension = "Gräfin",
                    givenName = "Adele Maude Veronika Mimi M.",
                    birthdate = Utils.getDate(1953, 10, 1),
                    gender = Gender.Female,
                    streetAddress = StreetAddress(
                        postalCode = 10176,
                        location = "Berlin",
                        street = "Dorfstrasse",
                        streetNumber = "1",
                        country = "GER"
                    )
                ),
                coverage = Coverage(
                    start = Utils.getDate(1993, 10, 7),
                    costCenter = CostCenter(
                        identification = 109500969,
                        countryCode = "GER",
                        "Test GKV-SV"
                    ),
                    insuranceType = InsuranceType.Member,
                    residencyPrinciple = ResidencyPrinciple.Berlin
                )
            )
        ).jsonObject,
        issuanceDate = date,
        issuer = URI.create(issuer)
    )

    @Test
    fun vsdCredential() {
        val credentialSerialized = json.encodeToString(vsdCredential)
        val credentialDeserialzed = json.decodeFromString<Credential>(credentialSerialized)
        assertEquals(vsdCredential.credentialSubject, credentialDeserialzed.credentialSubject)
        println(json.encodeToString(vsdCredential))
    }

    @Test
    fun expandAndCompactVsdCredential() {
        val expandedCredential = JsonLd.expand(vsdCredential.toJsonDocument()).options(defaultJsonLdOptions).get()
        println(json.encodeToString(json.parseToJsonElement(expandedCredential.toString())))
        val inputDocument = json.encodeToString(json.parseToJsonElement(expandedCredential.toString()))
            .byteInputStream()
            .use{
            JsonDocument.of(it)
        }
        val context = Credential(
            atContext = vsdCredential.atContext,
            type = vsdCredential.type
        ).toJsonDocument()
        val compactedCredential = JsonLd.compact(inputDocument, context).options(defaultJsonLdOptions).get()
        println(json.encodeToString(json.parseToJsonElement(compactedCredential.toString())))
    }

}