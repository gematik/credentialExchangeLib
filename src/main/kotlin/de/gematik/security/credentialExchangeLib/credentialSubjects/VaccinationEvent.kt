package de.gematik.security.credentialExchangeLib.credentialSubjects

import de.gematik.security.credentialExchangeLib.serializer.DateSerializer
import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable
import java.net.URI
import java.util.*

@Serializable
data class VaccinationEvent(
    val order: String? = null,
    val batchNumber: String? = null,
    val dateOfVaccination: @Serializable(with = DateSerializer::class) Date? = null,
    val administeringCentre: String? = null,
    val healthProfessional: String? = null,
    val countryOfVaccination: String? = null,
    val nextVaccinationDate: @Serializable(with = DateSerializer::class) Date? = null,
    val recipient: Recipient? = null,
    val vaccine: Vaccine? = null
) : JsonLdValue(listOf("VaccinationEvent"))

@Serializable
data class Recipient(
    val id: @Serializable(with = URISerializer::class) URI? = null,
    val birthDate: @Serializable(with = DateSerializer::class) Date? = null,
    val familyName: String? = null,
    val givenName: String? = null,
    val gender: String? = null
) : JsonLdValue(listOf("VaccineRecipient"))

@Serializable
data class Vaccine(
    val atcCode: String? = null,
    val disease: String? = null,
    val vaccine: String? = null,
    val medicalProductName: String? = null,
    val marketingAuthorizationHolder: String? = null
) : JsonLdValue(listOf("Vaccine"))