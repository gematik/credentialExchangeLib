package de.gematik.security.credentialExchangeLib.types

import de.gematik.security.credentialExchangeLib.serializer.JsonLdObjectSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI

@Serializable(JsonLdObjectSerializer::class)
public class JsonLdObject(
    private val content: Map<String, JsonElement>
) : Map<String, JsonElement> by content, LdObject {
    override val id: String? = content.get("id")?.jsonPrimitive?.content
    override val atContext: List<URI> = content.get("@context")?.jsonArray?.map{URI(it.jsonPrimitive.content)}?: listOf()
    override val type: List<String>? = content.get("type")?.jsonArray?.map{it.jsonPrimitive.content}
    public override fun equals(other: Any?): Boolean = content == other
    public override fun hashCode(): Int = content.hashCode()
}