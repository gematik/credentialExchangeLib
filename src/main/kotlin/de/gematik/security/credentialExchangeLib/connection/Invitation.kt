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

package de.gematik.security.credentialExchangeLib.connection

import de.gematik.security.credentialExchangeLib.json
import de.gematik.security.credentialExchangeLib.protocols.GoalCode
import de.gematik.security.credentialExchangeLib.serializer.URISerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import java.net.URI
import java.util.*

@Serializable
data class Invitation(
    val type: String = InvitationType.DIDCOMM_OUT_OF_BAND_2_0.uri.toString(),
    val id: String,
    val from: @Serializable(with = URISerializer::class) URI,
    val label: String? = null,
    val goal: String? = null,
    val goalCode: GoalCode? = null,
    val attachements: Attachements? = null
) {
    fun toBase64(): String {
        return Base64.getEncoder().encodeToString(json.encodeToString(this).toByteArray())
    }

    @Serializable
    data class Attachements(
        val id: String? = null, // Unique within scope of message
        val description: String? = null, // A human-readable description of the content.
        val filename: String? = null, // A hint about the name that might be used if this attachment is persisted as a file
        val mediaType: String? = null, // media type of the attached content
        val format: String? = null, // format of the attachment if the media_type is not sufficient
        val lastmod_time: String? = null, //Zoned_Date_Time UTC
        val data: Data // content
    )

    @Serializable
    data class Data(
        val jws: String? = null,  // detached content format
        val hash: String? = null, // hash of the content in multi-hash format
        val links: List<@Serializable(with = URISerializer::class) URI>? = null, //list of links to content
        val base64: String? = null, // content base64 format
        val json: String? = null, // content json format
    )

}

enum class InvitationType(val uri: URI) {
    DIDCOMM_OUT_OF_BAND_2_0(URI.create("https://didcomm.org/out-of-band/2.0/invitation")),
}