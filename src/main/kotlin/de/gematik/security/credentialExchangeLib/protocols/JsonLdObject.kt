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

import de.gematik.security.credentialExchangeLib.serializer.JsonLdObjectSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URI

@Serializable(JsonLdObjectSerializer::class)
public class JsonLdObject(
    private val content: Map<String, JsonElement>
) : Map<String, JsonElement> by content, LdObject(
    content.get("id")?.let{if(it is JsonPrimitive) it.jsonPrimitive.content else null},
    content.get("@context").let{
        when(it){
            is JsonArray -> it.map { URI(it.jsonPrimitive.content) }
            is JsonPrimitive -> listOf(URI(it.content))
            else -> emptyList()
        }
    },
    content.get("type").let{
        when(it){
            is JsonArray -> it.map { it.jsonPrimitive.content }
            is JsonPrimitive -> listOf(it.content)
            else -> emptyList()
        }
    }
) {
    val jsonContent = JsonObject(content)
    public override fun equals(other: Any?): Boolean = content == other
    public override fun hashCode(): Int = content.hashCode()
}