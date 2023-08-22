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
    val birthDate: @Serializable(with = DateSerializer::class) Date,
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
    val coPayment: CoPayment = CoPayment(
        status = false
    ),
    val dormantBenefitsEntitlement: DormantBenefitsEntitlement? = null
) : JsonLdValue(listOf("Coverage"))

@Serializable
data class CostCenter(
    val identification: Int,
    val countryCode: String,
    val name: String
) : JsonLdValue(listOf("CostCenter"))

@Serializable
enum class InsuranceType(code: Int) {
    Member(1),
    Family(3),
    PensionerAndFamily(5)
}

@Serializable
enum class ResidencyPrinciple(twoDigitCode: String) {
    SchleswigHolstein ("01"),
    Hamburg("02"),
    Bremen("03"),
    Niedersachsen("17"),
    WestfalenLippe("20"),
    Nordrhein("38"),
    Hessen("46"),
    RheinlandPfalz("51"),
    BadenWuerttemberg("52"),
    Bayern("71"),
    Berlin("72"),
    Saarland("73"),
    MecklenburgVorpommern("78"),
    Brandenburg("83"),
    SachsenAnhalt("88"),
    Thueringen("93"),
    Sachsen("98")
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
enum class Gender(code: Char) {
    Male('M'),
    Female('W'),
    Undefined('X')
}

@Serializable
data class CoPayment(
    val status: Boolean,
    val validUntil: @Serializable(with = DateSerializer::class) Date? = null
) : JsonLdValue(listOf("CoPayment"))

@Serializable
enum class SpecialGroupOfPersons(code:Int) {
    BSHG(4),
    BVG(6),
    SVA(7),
    SVA_pauschal(8),
    Asyl(9)
}

@Serializable
enum class DmpMark(code: Int) {
    DiabetesMellitusType2(1),
    BreastCancer(2),
    CHD_CoronaryHeartDisease(3),
    DiabetesMellitusType1(4),
    AsthmaBronchiale(5),
    COPD_ChronicObstructivePulmonaryDisease(6),
    ChronicCardiacInsufficiency(7),
    Depression(8),
    SevereBackPain(9)
}

@Serializable
data class SelectiveContracts(
    val medical: SelectiveContractStatus,
    val dental: SelectiveContractStatus,
    val contractType: ContractType,
) : JsonLdValue(listOf("SelectiveContracts"))

@Serializable
enum class SelectiveContractStatus(code: Int) {
    available(1),
    notAvailable(0),
    notUsed(9)
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
enum class DormancyType(code: Int) {
    complete(1),
    limited(2)
}