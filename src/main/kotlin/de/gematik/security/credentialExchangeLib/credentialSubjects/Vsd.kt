package de.gematik.security.credentialExchangeLib.credentialSubjects

import de.gematik.security.credentialExchangeLib.serializer.DateSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.util.*

@Serializable
data class Insurance(
    val insurant: Insurant,
    val coverage: Coverage? = null
) : JsonLdValue(listOf("Insurance"))

@Serializable
data class Insurant(
    val insurantId: String,
    val familyName: String,
    val givenName: String,
    val nameExtension: String? = null,
    val birthdate: @Serializable(with = DateSerializer::class) Date,
    val gender: Gender,
    val academicTitel: String? = null,
    val streetAddress: StreetAddress? = null,
    val postBoxAddress: PostBoxAddress? = null
) : JsonLdValue(listOf("Insurant"))

@Serializable
data class Coverage(
    val start: @Serializable(with = DateSerializer::class) Date,
    val end: @Serializable(with = DateSerializer::class) Date? = null,
    val costCenter: CostCenter? = null,
    val insuranceType: InsuranceType? = null,
    val reimbursement: Reimbursement? = null,
    val residencyPrinciple: ResidencyPrinciple? = null,
    val specialGroupOfPersons: SpecialGroupOfPersons? = null,
    val dmpMark: DmpMark? = null,
    val selectiveContracts: SelectiveContracts? = null,
    val coPayment: CoPayment? = null,
    val dormantBenefitsEntitlement: DormantBenefitsEntitlement? = null
) : JsonLdValue(listOf("Coverage"))

@Serializable
data class CostCenter(
    val identification: Int,
    val countryCode: String,
    val name: String
) : JsonLdValue(listOf("CostCenter"))

@Serializable
enum class InsuranceType {
    @SerialName("1")  Member,
    @SerialName("3")  Family,
    @SerialName("5")  PensionerAndFamily
}

@Serializable
enum class ResidencyPrinciple {
    @SerialName("01")  SchleswigHolstein,
    @SerialName("02")  Hamburg,
    @SerialName("03")  Bremen,
    @SerialName("17")  Niedersachsen,
    @SerialName("20")  WestfalenLippe,
    @SerialName("38")  Nordrhein,
    @SerialName("46")  Hessen,
    @SerialName("51")  RheinlandPfalz,
    @SerialName("52")  BadenWuerttemberg,
    @SerialName("71")  Bayerns,
    @SerialName("72")  Berlin,
    @SerialName("73")  Saarland,
    @SerialName("78")  MecklenburgVorpommern,
    @SerialName("83")  Brandenburg,
    @SerialName("88")  SachsenAnhalt,
    @SerialName("93")  Thueringen,
    @SerialName("98")  Sachsen
}

@Serializable
data class Reimbursement(
    val medicalCare: Boolean,
    val dentalCare: Boolean,
    val inpatientSector: Boolean,
    val initiatedServices: Boolean
) : JsonLdValue(listOf("Reimbursement"))

@Serializable
data class PostBoxAddress(
    val postalCode: Int,
    val location: String,
    val postBoxNumber: String,
    val country: String
) : JsonLdValue(listOf("PostBoxAddress"))

@Serializable
data class StreetAddress(
    val postalCode: Int,
    val location: String,
    val street: String,
    val streetNumber: String,
    val country: String
) : JsonLdValue(listOf("StreetAddress"))

@Serializable
enum class Gender {
    @SerialName("M") Male,
    @SerialName("W") Female,
    @SerialName("X") Undefined
}

@Serializable
data class CoPayment(
    val status: Boolean,
    val validUntil: @Serializable(with = DateSerializer::class) Date
) : JsonLdValue(listOf("CoPayment"))

@Serializable
enum class SpecialGroupOfPersons {
    @SerialName("4") BSHG,
    @SerialName("6") BVG,
    @SerialName("7") SVA,
    @SerialName("8") SVA_pauschal,
    @SerialName("9") Asyl
}

@Serializable
enum class DmpMark {
    @SerialName("1") DiabetesMellitusTyp2,
    @SerialName("2") Brustkrebs,
    @SerialName("3") KoronareHerzkrankheit,
    @SerialName("4") DiabetesMellitusTyp1,
    @SerialName("5") AsthmaBronchiale,
    @SerialName("6") COPD_ChronicObstructivePulmonaryDisease,
    @SerialName("7") ChronischeHerzinsuffizienz,
    @SerialName("8") Depression,
    @SerialName("9") Rueckenschmerz
}

@Serializable
data class SelectiveContracts(
    val medical: SelectiveContractStatus,
    val dental: SelectiveContractStatus,
    val contractType: SelectiveContractStatus
) : JsonLdValue(listOf("SelectivContract"))

@Serializable
enum class SelectiveContractStatus {
    @SerialName("1") selectivContractAvailable,
    @SerialName("0") selectivContractNotAvailable,
    @SerialName("9") selectivContractMarkNotUsed
}

@Serializable
data class ContractType(
    val generalPractionerCare: Boolean,
    val structuredTreatmentProgram: Boolean,
    val integratedCare: Boolean
) : JsonLdValue(listOf("ContractType"))

@Serializable
data class DormantBenefitsEntitlement(
    val start: @Serializable(with = DateSerializer::class) Date,
    val end: @Serializable(with = DateSerializer::class) Date,
    val dormancyType: DormancyType
) : JsonLdValue(listOf("DormantBenefitsEntitlement"))

@Serializable
enum class DormancyType {
    @SerialName("1") complete,
    @SerialName("2") limited
}