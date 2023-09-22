package de.gematik.security.credentialExchangeLib.credentialSubjects

import de.gematik.security.credentialExchangeLib.protocols.LdObject
import kotlinx.serialization.Serializable

@Serializable
data class VaccinationEvent(
    val order: String? = null,
    val batchNumber: String? = null,
    val dateOfVaccination: String? = null,
    val administeringCentre: String? = null,
    val healthProfessional: String? = null,
    val countryOfVaccination: String? = null,
    val nextVaccinationDate: String? = null,
    val recipient: Recipient? = null,
    val vaccine: Vaccine? = null
) : LdObject(type = listOf("VaccinationEvent"))

@Serializable
data class Recipient(
    val birthDate: String? = null,
    val familyName: String? = null,
    val givenName: String? = null,
    val gender: String? = null
) : LdObject(type = listOf("VaccineRecipient"))

@Serializable
data class Vaccine(
    val atcCode: String? = null,
    val disease: String? = null,
    val vaccine: String? = null,
    val medicalProductName: String? = null,
    val marketingAuthorizationHolder: String? = null
) : LdObject(type = listOf("Vaccine"))