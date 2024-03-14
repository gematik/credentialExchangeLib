/*
 * Copyright 2021-2024, gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 */

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