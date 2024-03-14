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
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI

@Serializable
open class LdObject {
    constructor(id: String? = null, atContext: List<URI>? = null, type: List<String>){
        this.id = id
        this.atContext = atContext
        this.type = type
    }
    var id: String? = null
    @SerialName("@context") private var _atContext: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String>? = null
    var atContext
        get() = _atContext?.map { URI.create(it) }
        set(value) {
            _atContext = value?.map { it.toString() }
        }
    @Required var type: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<String>

    abstract class Defaults {

        abstract val DEFAULT_JSONLD_CONTEXTS: List<URI>
        abstract val DEFAULT_JSONLD_TYPES: List<String>
    }
}