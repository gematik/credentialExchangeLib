package de.gematik.security.credentialExchangeLib

import de.gematik.security.credentialExchangeLib.crypto.KeyPair
import de.gematik.security.credentialExchangeLib.crypto.ProofType
import de.gematik.security.credentialExchangeLib.crypto.ecdsa.P256CryptoCredentials
import de.gematik.security.credentialExchangeLib.crypto.ecdsa.P256K1CryptoCredentials
import de.gematik.security.credentialExchangeLib.extensions.deepCopy
import de.gematik.security.credentialExchangeLib.extensions.hexToByteArray
import de.gematik.security.credentialExchangeLib.protocols.Credential
import de.gematik.security.credentialExchangeLib.protocols.LdProof
import de.gematik.security.credentialExchangeLib.protocols.ProofPurpose
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Test
import java.net.URI
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.*
import kotlin.test.assertEquals

class EcdsaProofTest {
    val p256CryptoCredentials = P256CryptoCredentials(
        KeyPair(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721".hexToByteArray(),
            P256CryptoCredentials.createPublicKey("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721".hexToByteArray())
        )
    )

    val p256K1CryptoCredentials = P256K1CryptoCredentials(
        KeyPair(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721".hexToByteArray(),
            P256K1CryptoCredentials.createPublicKey("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721".hexToByteArray())
        )
    )

    val date = ZonedDateTime.of(2023,8,24,13,6,21,408000, ZoneId.of("UTC"))

    val ldProofP256 = LdProof(
        atContext = listOf(URI("https://www.w3.org/2018/credentials/v1")),
        type = listOf(ProofType.EcdsaSecp256r1Signature2019.name),
        created = date,
        proofPurpose = ProofPurpose.ASSERTION_METHOD,
        verificationMethod = p256CryptoCredentials.verificationMethod
    )

    val ldProofP256K1 = LdProof(
        atContext = listOf(URI("https://www.w3.org/2018/credentials/v1")),
        type = listOf(ProofType.EcdsaSecp256k1Signature2019.name),
        created = date,
        proofPurpose = ProofPurpose.ASSERTION_METHOD,
        verificationMethod = p256K1CryptoCredentials.verificationMethod
    )

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
        issuer = p256CryptoCredentials.didKey
    )

    @Test
    fun testP256CryptoCredentials() {
        assertEquals("did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP", p256CryptoCredentials.didKey.toString())
        println(p256CryptoCredentials.didKey)
        assertEquals("21DadENJx6PyPsAcUo5huAbyQKdcMd5zftFJzGky4oYSH", p256CryptoCredentials.verKey)
        println(p256CryptoCredentials.verKey)
        assertEquals(
            "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
            p256CryptoCredentials.verificationMethod.toString()
        )
        println(p256CryptoCredentials.verificationMethod)
    }

    @Test
    fun signVerifyCredentialP256() {
        val signedCredential =
            credential.deepCopy().apply { sign(ldProofP256, p256CryptoCredentials.keyPair.privateKey!!) }
        val result = signedCredential.verify()
        assert(result)
        println(json.encodeToString(signedCredential))
    }

    @Test
    fun testP256K1CryptoCredentials() {
        assertEquals("did:key:zQ3shhe14AeNbkLWqrZxJRkj23i88k3KCvzDeX6a9gsCoQ89a", p256K1CryptoCredentials.didKey.toString())
        println(p256K1CryptoCredentials.didKey)
        assertEquals("wgr3KVu8RhHxcUGt3fqyE7kh6H8EeSB7bApMPXXgBeHr", p256K1CryptoCredentials.verKey)
        println(p256K1CryptoCredentials.verKey)
        assertEquals(
            "did:key:zQ3shhe14AeNbkLWqrZxJRkj23i88k3KCvzDeX6a9gsCoQ89a#zQ3shhe14AeNbkLWqrZxJRkj23i88k3KCvzDeX6a9gsCoQ89a",
            p256K1CryptoCredentials.verificationMethod.toString()
        )
        println(p256K1CryptoCredentials.verificationMethod)
    }

    @Test
    fun signVerifyCredentialP256K1() {
        val signedCredential =
            credential.deepCopy().apply { sign(ldProofP256K1, p256K1CryptoCredentials.keyPair.privateKey!!) }
        val result = signedCredential.verify()
        assert(result)
        println(json.encodeToString(signedCredential))
    }

}

