package de.gematik.security.credentialExchangeLib

import de.gematik.security.credentialExchangeLib.crypto.ProofType
import de.gematik.security.credentialExchangeLib.crypto.dilithium.*
import de.gematik.security.credentialExchangeLib.extensions.deepCopy
import de.gematik.security.credentialExchangeLib.protocols.Credential
import de.gematik.security.credentialExchangeLib.protocols.JsonLdObject
import de.gematik.security.credentialExchangeLib.protocols.LdProof
import de.gematik.security.credentialExchangeLib.protocols.ProofPurpose
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Test
import java.net.URI
import java.time.ZoneId
import java.time.ZonedDateTime

class DilithiumProofTest {

    val message = "very important private message".toByteArray()
    val dilithium2CryptoCredentials = Dilithium2CryptoCredentials(Dilithium2CryptoCredentials.generateKeyPair())
    val dilithium3CryptoCredentials = Dilithium3CryptoCredentials(Dilithium3CryptoCredentials.generateKeyPair())
    val dilithium5CryptoCredentials = Dilithium5CryptoCredentials(Dilithium5CryptoCredentials.generateKeyPair())

    val date = ZonedDateTime.of(2023,8,24,13,6,21,408000, ZoneId.of("UTC"))

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
                        "id" to JsonPrimitive("did:key:base58-coded-public-key-of-recepient"),
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
        issuer = dilithium2CryptoCredentials.didKey
    )

    @Test
    fun signVerifySingleMessage(){
        // sign message
        var signature = Dilithium2Signer(dilithium2CryptoCredentials.keyPair).sign(listOf( message))
        //verify message
        var isSuccess = Dilithium2Verifier(dilithium2CryptoCredentials.keyPair.publicKey!!).verify(listOf(message), signature)
        assert(isSuccess)
        // sign message
        signature = Dilithium3Signer(dilithium3CryptoCredentials.keyPair).sign(listOf( message))
        //verify message
        isSuccess = Dilithium3Verifier(dilithium3CryptoCredentials.keyPair.publicKey!!).verify(listOf(message), signature)
        assert(isSuccess)
        // sign message
        signature = Dilithium5Signer(dilithium5CryptoCredentials.keyPair).sign(listOf( message))
        //verify message
        isSuccess = Dilithium5Verifier(dilithium5CryptoCredentials.keyPair.publicKey!!).verify(listOf(message), signature)
        assert(isSuccess)
    }

    @Test
    fun signVerifyCredentialDilithium2(){
        val ldProof = LdProof(
            atContext = listOf(URI("https://w3id.org/security/dilithium/v1")),
            type = listOf(ProofType.Dilithium2Signature2023.name),
            created = date,
            proofPurpose = ProofPurpose.ASSERTION_METHOD,
            verificationMethod = dilithium2CryptoCredentials.verificationMethod
        )
        val signedCredential =
            credential.deepCopy().apply { sign(ldProof, dilithium2CryptoCredentials.keyPair.privateKey!!) }
        println(json.encodeToString(signedCredential))
        val result = signedCredential.verify()
        assert(result)
    }

    @Test
    fun signVerifyDeriveAndVerifyDerivedCredential(){
        // sign
        val ldProof = LdProof(
            atContext = listOf(URI("https://w3id.org/security/dilithium/v1")),
            type = listOf(ProofType.Dilithium2SdSignature2023.name),
            created = date,
            proofPurpose = ProofPurpose.ASSERTION_METHOD,
            verificationMethod = dilithium2CryptoCredentials.verificationMethod
        )
        val signedCredential =
            credential.deepCopy().apply { sign(ldProof, dilithium2CryptoCredentials.keyPair.privateKey!!) }
        println(json.encodeToString(signedCredential))
        // verify
        var result = signedCredential.verify()
        assert(result)
        // derive
        val frame = Credential(
            // frame requesting complete vaccination credential
            atContext = Credential.DEFAULT_JSONLD_CONTEXTS + listOf(URI.create("https://w3id.org/vaccination/v1")),
            type = Credential.DEFAULT_JSONLD_TYPES + listOf("VaccinationCertificate")
        )
        val derivedCredential = signedCredential.derive(frame)
        println(json.encodeToString(derivedCredential))
        //verify derived credential
        result = derivedCredential.verify()
        assert(result)
    }

    @Test
    fun signVerifyDeriveAndVerifyDerivedCredentialSelective(){
        // sign
        val ldProof = LdProof(
            atContext = listOf(URI("https://w3id.org/security/dilithium/v1")),
            type = listOf(ProofType.Dilithium2SdSignature2023.name),
            created = date,
            proofPurpose = ProofPurpose.ASSERTION_METHOD,
            verificationMethod = dilithium2CryptoCredentials.verificationMethod
        )
        val signedCredential =
            credential.deepCopy().apply { sign(ldProof, dilithium2CryptoCredentials.keyPair.privateKey!!) }
        println(json.encodeToString(signedCredential))
        // verify
        var result = signedCredential.verify()
        assert(result)
        // derive
        val frame = Credential(
            // frame requesting vaccination status only
            atContext = Credential.DEFAULT_JSONLD_CONTEXTS + listOf(URI.create("https://w3id.org/vaccination/v1")),
            type = Credential.DEFAULT_JSONLD_TYPES + listOf("VaccinationCertificate"),
            credentialSubject = JsonLdObject(
                mapOf(
                    "@explicit" to JsonPrimitive(true),
                    "@requireAll" to JsonPrimitive(true),
                    "type" to JsonArray(listOf(JsonPrimitive("VaccinationEvent"))),
                    "order" to JsonArray(listOf(JsonPrimitive("3/3"))),
                    "recipient" to JsonObject(
                        mapOf(
                            "@explicit" to JsonPrimitive(true),
                            "type" to JsonArray(listOf(JsonPrimitive("VaccineRecipient"))),
                            "id" to JsonObject(mapOf())
                        )
                    )
                )
            ),
        )
        val derivedCredential = signedCredential.derive(frame)
        println(json.encodeToString(derivedCredential))
        //verify derived credential
        result = derivedCredential.verify()
        assert(result)
    }

}