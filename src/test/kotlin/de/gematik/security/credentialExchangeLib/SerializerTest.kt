package de.gematik.security.credentialExchangeLib

import de.gematik.security.mobilewallet.extensions.toString
import de.gematik.security.mobilewallet.serializer.URISerializer
import de.gematik.security.mobilewallet.serializer.UUIDSerializer
import de.gematik.security.mobilewallet.types.*
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Test

import java.net.URI
import java.util.*
import kotlin.test.assertEquals

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
class SerializerTest {
    @Test
    fun serializeURI() {
        val uri = URI("https://example.com")
        val serializedUri = Json.encodeToString(URISerializer, uri)
        assertEquals(uri, Json.decodeFromString(URISerializer, serializedUri))
    }

    @Test
    fun serializeUUID() {
        val uuid = UUID.randomUUID()
        val serializedUUID = Json.encodeToString(UUIDSerializer, uuid)
        assertEquals(uuid, Json.decodeFromString(UUIDSerializer, serializedUUID))
    }

    @Test
    fun serializeInvitation() {
        val atId = UUID.randomUUID()
        val services = listOf(Service(SERVICE_PX_OVER_HTTP, URI.create("http://example.com")))
        val invitation = Invitation(MESSAGE_INVITATION, atId, "test", "goal_code_test", "goal_test", services)
        val serializedInvitation = Json.encodeToString(invitation)
        assertEquals(invitation, Json.decodeFromString<Invitation>(serializedInvitation))
        println(Json.encodeToJsonElement(invitation).jsonObject.toString(3))
    }

    @Test
    fun serializeCredential() {
        val credential = Credential(
            context = listOf(URI.create("https://w3id.org/vaccination/v1")),
            type = listOf("VaccinationCertificate"),
            credentialSubject = mapOf(
                "type" to "VaccinationEvent",
                "batchNumber" to "1626382736",
                "dateOfVaccination" to "2021-06-23T13:40:12Z",
                "administeringCentre" to "Praxis Sommergarten",
                "healthProfessional" to "883110000015376",
                "countryOfVaccination" to "GE",
                "nextVaccinationDate" to "2021-08-16T13:40:12Z",
                "order" to "3/3",
                "recipient" to mapOf(
                    "type" to "VaccineRecipient",
                    "givenName" to "Marion",
                    "familyName" to "Mustermann",
                    "gender" to "Female",
                    "birthDate" to "1961-08-17"
                ),
                "vaccine" to mapOf(
                    "type" to "Vaccine",
                    "atcCode" to "J07BX03",
                    "medicinalProductName" to "COVID-19 Vaccine Moderna",
                    "marketingAuthorizationHolder" to "Moderna Biotech"
                )
            ),
            issuanceDate = Date(),
            issuer = URI.create("did:key:test")
        )
        val serializedCredential = Json.encodeToString(credential)
        assertEquals(credential, Json.decodeFromString<Credential>(serializedCredential))
        println(credential.toJsonObject().toString(3))
    }

}