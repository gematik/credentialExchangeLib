package de.gematik.security.credentialExchangeLib

import de.gematik.security.credentialExchangeLib.credentialSubjects.*
import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import de.gematik.security.credentialExchangeLib.crypto.ProofType
import de.gematik.security.credentialExchangeLib.crypto.bbs.BbsCryptoCredentials
import de.gematik.security.credentialExchangeLib.extensions.*
import de.gematik.security.credentialExchangeLib.protocols.*
import io.github.novacrypto.base58.Base58
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Test
import java.net.URI
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.*
import kotlin.test.assertEquals

class BbsProofTests {

    val credentialIssuer = BbsCryptoCredentials(
        KeyPair(
            "4b72cad121e0459dce3c5ead7683e82185459a77ac33a9bcd84423c36683acf5".hexToByteArray(),
            "9642f47f8f970fe5a36f67d74841cf0885141ccc8eae92685b4dbda5891b42ab132ab0b8c8df8ec11316bdddddbed330179ca7dc7c6dbbd7bf74584831087bb9884d504a76afd4d8f03c14c1e6acccb7bf76b4e2068725456f65fca1bdc184b5".hexToByteArray()
        )
    )
    val credentialHolder = BbsCryptoCredentials(
        KeyPair(
            "4318a7863ecbf9b347f3bd892828c588c20e61e5fa7344b7268643adb5a2bd4e".hexToByteArray(),
            "a21e0d512342b0b6ebf0d86ab3a2cef2a57bab0c0eeff0ffebad724107c9f33d69368531b41b1caa5728730f52aea54817b087f0d773cb1a753f1ede255468e88cea6665c6ce1591c88b079b0c4f77d0967d8211b1bc8687213e2af041ba73c4".hexToByteArray()
        )
    )

    val date = ZonedDateTime.of(2023, 8, 24, 13, 6, 21, 408000000, ZoneId.of("UTC"))
    val presentationDefinitionId = UUID.fromString("250787ea-f892-11ed-b67e-0242ac120002")
    val inputDescriptorId = "3aa55a6e-f892-11ed-b67e-0242ac120002"

    val ldProofIssuer = LdProof(
        type = listOf(ProofType.BbsBlsSignature2020.name),
        created = date,
        proofPurpose = ProofPurpose.ASSERTION_METHOD,
        verificationMethod = credentialIssuer.verificationMethod
    )

    val ldProofHolder = LdProof(
        type = listOf(ProofType.BbsBlsSignature2020.name),
        created = date,
        proofPurpose = ProofPurpose.AUTHENTICATION,
        verificationMethod = credentialHolder.verificationMethod
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

    val emptyCredentialFrame = Credential(
        atContext = Credential.DEFAULT_JSONLD_CONTEXTS + listOf(
            URI("https://w3id.org/vaccination/v1")
        ),
        type = Credential.DEFAULT_JSONLD_TYPES + listOf(
            "VaccinationCertificate"
        )
    )

    val credentialFrame = Credential(
        atContext = listOf(
            URI.create("https://www.w3.org/2018/credentials/v1"),
            URI.create("https://w3id.org/vaccination/v1")
        ),
        type = listOf(
            "VerifiableCredential",
            "VaccinationCertificate"
        ),
        credentialSubject = JsonLdObject(
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

    @Test
    fun testBbsCryptoCredentials() {
        val cryptoCredentials = BbsCryptoCredentials(BbsCryptoCredentials.createKeyPair())
        assert(cryptoCredentials.didKey.toString().startsWith("did:key:zUC"))
        println(cryptoCredentials.didKey)
        assertEquals(96, Base58.base58Decode(cryptoCredentials.verKey).size)
        println(cryptoCredentials.verKey)
        assertEquals(
            cryptoCredentials.verificationMethod.toString(),
            cryptoCredentials.didKey.toString() + "#" + cryptoCredentials.didKey.toString().drop(8)
        )
        println(cryptoCredentials.verificationMethod)
    }

    @Test
    fun signVerifyCredential() {
        val signedCredential =
            credential.deepCopy().apply { sign(ldProofIssuer, credentialIssuer.keyPair.privateKey!!) }
        val result = signedCredential.verify()
        assert(result)
        println(json.encodeToString(signedCredential))
    }

    @Test
    fun deriveAndVerifyCredential() {
        val signedCredential =
            credential.deepCopy().apply { sign(ldProofIssuer, credentialIssuer.keyPair.privateKey!!) }
        val derivedCredential = signedCredential.derive(credentialFrame)
        val result = derivedCredential.verify()
        assert(result)
        println(json.encodeToString(derivedCredential))
    }

    @Test
    fun deriveAndVerifyVsdCredential() {

        val vsdCredential = Credential(
            atContext = Credential.DEFAULT_JSONLD_CONTEXTS + listOf(URI.create("https://gematik.de/vsd/v1")),
            type = Credential.DEFAULT_JSONLD_TYPES + listOf("InsuranceCertificate"),
            credentialSubject = Insurance(
                insurant = Insurant(
                    insurantId = "X110403565",
                    familyName = "Schühmann",
                    nameExtension = "Gräfin",
                    givenName = "Adele Maude Veronika Mimi M.",
                    birthDate = getZonedDate(1953, 10, 1).toIsoInstantString(),
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
                    start = getZonedDate(1993, 10, 7).toIsoInstantString(),
                    costCenter = CostCenter(
                        identification = 109500969,
                        countryCode = "GER",
                        name = "Test GKV-SV"
                    ),
                    insuranceType = InsuranceType.Member,
                    residencyPrinciple = ResidencyPrinciple.Berlin
                )
            ).toJsonLdObject(),
            issuanceDate = date,
            issuer = credentialIssuer.didKey
        )

        val signedCredential = vsdCredential.apply { sign(ldProofIssuer, credentialIssuer.keyPair.privateKey!!) }

        val frameString = """
            {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://gematik.de/vsd/v1"
                ],
                "type": [
                    "VerifiableCredential",
                    "InsuranceCertificate"
                ]
            }
            """.trimIndent()
        val frame = json.decodeFromString<Credential>(frameString)
        val derivedCredential = signedCredential.derive(frame)
        val result = derivedCredential.verify()
        assert(result)
        println(json.encodeToString(derivedCredential))
    }

    @Test
    fun signVerifyPresentation() {
        val signedPresentation = Presentation(
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
            verifiableCredential = listOf(credential.deepCopy().apply {
                sign(ldProofIssuer, credentialIssuer.keyPair.privateKey!!)
            }.derive(emptyCredentialFrame))
        ).apply {
            sign(ldProofHolder, credentialHolder.keyPair.privateKey!!)
        }
        val result = signedPresentation.verify()
        assert(result)
        println(json.encodeToString(signedPresentation))
    }

}