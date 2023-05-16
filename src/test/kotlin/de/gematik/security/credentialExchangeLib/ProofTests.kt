package de.gematik.security.credentialExchangeLib

import bbs.signatures.KeyPair
import de.gematik.security.credentialExchangeLib.extensions.verify
import de.gematik.security.credentialExchangeLib.bbs.BbsPlusSigner
import de.gematik.security.credentialExchangeLib.extensions.hexToByteArray
import de.gematik.security.credentialExchangeLib.types.LdProof
import de.gematik.security.credentialExchangeLib.types.ProofPurpose
import de.gematik.security.mobilewallet.types.Credential
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Test
import java.net.URI
import java.util.*

class ProofTests {

    val didKeyIssuer =
        "did:key:zUC78bhyjquwftxL92uP5xdUA7D7rtNQ43LZjvymncP2KTXtQud1g9JH4LYqoXZ6fyiuDJ2PdkNU9j6cuK1dsGjFB2tEMvTnnHP7iZJomBmmY1xsxBqbPsCMtH6YmjP4ocfGLwv"
    val verkeyIssuer =
        "tmA6gAFiKH67j6EXv1wFrorCcc4C24ndsYPxJkvDaaB61JfNyUu8FtbAeYCr9gBG55cWbLWemqYexSHWi1PXM5MWZaZgpeFdSucQry8u44q1bHVzJw2FiUgaJYeBE4WPrLc"
    val keyPairIssuer = KeyPair(
        "9642f47f8f970fe5a36f67d74841cf0885141ccc8eae92685b4dbda5891b42ab132ab0b8c8df8ec11316bdddddbed330179ca7dc7c6dbbd7bf74584831087bb9884d504a76afd4d8f03c14c1e6acccb7bf76b4e2068725456f65fca1bdc184b5".hexToByteArray(),
        "4b72cad121e0459dce3c5ead7683e82185459a77ac33a9bcd84423c36683acf5".hexToByteArray()
    )
    val verificationMethodIssuer = URI.create("${didKeyIssuer}#${didKeyIssuer.drop(8)}")


    val didKeyHolder =
        "did:key:zUC7CgahEtPMHR2JsTnFSbhjFE6bYAm5i2vbFWRUdSUNc45zFAg3rCA6UVoYcDzU5DHAk1HuLV5tgcd6edL8mKLoDRhbz7qzav5yzkDWWgZMh8wTieyjcXtoTSmxNq96nWUgP5V"
    val verkeyHolder =
        "xr2pBCj7voA6TX7QGf1WwvjgHtSsg4NfP7qf9b1ZsAjBqZiR9Xkwg3qsTEeDYujXbnt2J5E5Jj58hkc1c415PUAtBmwtdGxVj6X7cTvVDBobMke8XbihHeMyueQDCxKotUB"
    val keyPairHolder = KeyPair(
        "a21e0d512342b0b6ebf0d86ab3a2cef2a57bab0c0eeff0ffebad724107c9f33d69368531b41b1caa5728730f52aea54817b087f0d773cb1a753f1ede255468e88cea6665c6ce1591c88b079b0c4f77d0967d8211b1bc8687213e2af041ba73c4".hexToByteArray(),
        "4318a7863ecbf9b347f3bd892828c588c20e61e5fa7344b7268643adb5a2bd4e".hexToByteArray()
    )
    val verificationMethodHolder = URI.create("${didKeyHolder}#${didKeyHolder.drop(8)}")

    @Test
    fun signVerifyCredential() {
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
            issuanceDate = Date(1684152736408),
            issuer = URI.create(didKeyIssuer)
        )
        credential.sign(
            LdProof(
                atContext = listOf(),
                type = listOf("https://w3id.org/security#BbsBlsSignature2020"),
                creator = URI.create(didKeyIssuer),
                created = Date(1684152736408),
                proofPurpose = ProofPurpose.ASSERTION_METHOD,
                verificationMethod = verificationMethodIssuer,
            ),
            BbsPlusSigner(keyPairIssuer)
        )
        val result = credential.proof?.get(0)?.verify(credential, proofPurpose =  ProofPurpose.ASSERTION_METHOD)?:false
        assert(result)
        println(json.encodeToString(credential))
    }

}