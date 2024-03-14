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

package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.util.*

@Serializable
class PresentationSubmission : LdObject {
    constructor(
        id: String? = null,
        definitionId: UUID,
        descriptorMap: List<DescriptorMapEntry>
    ) : super (id, DEFAULT_JSONLD_CONTEXTS, DEFAULT_JSONLD_TYPES){
        _definitionId = definitionId.toString()
        this.descriptorMap = descriptorMap
    }

    @SerialName("definition_id") private val _definitionId: String
    val definitionId
        get() = UUID.fromString(_definitionId)
    @SerialName("descriptor_map") val descriptorMap: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<DescriptorMapEntry>

    companion object : Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://identity.foundation/presentation-exchange/submission/v1")
        )
        override val DEFAULT_JSONLD_TYPES = listOf(
            "PresentationSubmission"
        )
    }

    @Serializable
    data class DescriptorMapEntry(val id: String, val format: ClaimFormat, val path: String)
}