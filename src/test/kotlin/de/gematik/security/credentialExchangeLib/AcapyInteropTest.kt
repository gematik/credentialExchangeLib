package de.gematik.security.credentialExchangeLib

import de.gematik.security.credentialExchangeLib.protocols.Credential
import kotlinx.serialization.encodeToString
import org.junit.jupiter.api.Test

class AcapyInteropTest {
    val acapyCredential = """
        {
           "proof": {
              "proofPurpose": "assertionMethod",
              "type": "BbsBlsSignature2020",
              "verificationMethod": "did:key:zUC7CtC4GPsNK5hMNjCzUmaPTiobg6WtapwD2ZdqDA4vteVLjSeeGGDwKL8H4wodtaFMMWCaWrCoGrKJmS5sG75RQG2zKqqnYJwQZL2Rj3ZiN5737SEFRZYpyocoEWgYWvCENJn#zUC7CtC4GPsNK5hMNjCzUmaPTiobg6WtapwD2ZdqDA4vteVLjSeeGGDwKL8H4wodtaFMMWCaWrCoGrKJmS5sG75RQG2zKqqnYJwQZL2Rj3ZiN5737SEFRZYpyocoEWgYWvCENJn",
              "proofValue": "lHuMOgE4CY1HJLOBQ1FKNovzoS95TkiI8ti3ycLNytx5bN6QZ59PDyLNkKlnY4qrGLsnSzuM9qSi/TyXRpT/fNBbTXbuxpFFnM6aAL+UuI5gENyDnecHFhV0i2k0sG5BqmfDKt12exnYen6RMZMhCg==",
              "created": "2023-08-23T08:46:20.419948+00:00"
           },
           "type": [
              "VerifiableCredential",
              "VaccinationCertificate"
           ],
           "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://w3id.org/vaccination/v1",
              "https://w3id.org/security/bbs/v1"
           ],
           "issuanceDate": "2023-08-23T08:46:19.718701300Z",
           "credentialSubject": {
              "vaccine": {
                 "type": "Vaccine",
                 "atcCode": "J07BX03",
                 "medicinalProductName": "COVID-19 Vaccine Moderna",
                 "marketingAuthorizationHolder": "Moderna Biotech"
              },
              "nextVaccinationDate": "2021-08-16T13:40:12Z",
              "countryOfVaccination": "GE",
              "dateOfVaccination": "2021-06-23T13:40:12Z",
              "recipient": {
                 "type": "VaccineRecipient",
                 "gender": "Female",
                 "birthDate": "1961-08-17",
                 "givenName": "Marion",
                 "familyName": "Mustermann"
              },
              "id": "did:key:zUC7FpCx2XPTbBzeXvhsHtwzX9HFcH71UKRmcMZBN8xCeFkiJBBfyA7kgp6TEgHoDorEk1TcKziqE74b3ZNZuE9C9GoDbFTXv2qGGP16JWoPCy5Le84vEvRuWWE5LHKN3x4KFXX",
              "type": "VaccinationEvent",
              "administeringCentre": "Praxis Sommergarten",
              "batchNumber": "1626382736",
              "healthProfessional": "883110000015376",
              "order": "3/3"
           },
           "issuer": "did:key:zUC7CtC4GPsNK5hMNjCzUmaPTiobg6WtapwD2ZdqDA4vteVLjSeeGGDwKL8H4wodtaFMMWCaWrCoGrKJmS5sG75RQG2zKqqnYJwQZL2Rj3ZiN5737SEFRZYpyocoEWgYWvCENJn"
        }
    """.trimIndent()

    @Test
    fun verifyAcapyW3cCredentialWithBbsSignature(){
        val credential = json.decodeFromString<Credential>(acapyCredential)
        println(json.encodeToString(credential))
        val isVerified = credential.verify()
        assert(isVerified)
    }

}