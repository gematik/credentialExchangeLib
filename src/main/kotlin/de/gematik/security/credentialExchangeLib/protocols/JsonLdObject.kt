package de.gematik.security.credentialExchangeLib.protocols

import de.gematik.security.credentialExchangeLib.serializer.JsonLdObjectSerializer
import de.gematik.security.credentialExchangeLib.serializer.UnwrappingSingleValueJsonArrays
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URI

@Serializable(JsonLdObjectSerializer::class)
public class JsonLdObject(
    private val content: Map<String, JsonElement>
) : Map<String, JsonElement> by content, LdObject(
    content.get("id")?.jsonPrimitive?.content,
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