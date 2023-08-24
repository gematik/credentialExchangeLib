package de.gematik.security.credentialExchangeLib.extensions

import com.apicatalog.jsonld.JsonLd
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.rdf.RdfDataset
import com.apicatalog.rdf.io.nquad.NQuadsWriter
import de.gematik.security.credentialExchangeLib.defaultJsonLdOptions
import de.gematik.security.credentialExchangeLib.json
import de.gematik.security.credentialExchangeLib.protocols.LdObject
import io.setl.rdf.normalization.RdfNormalize
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import java.io.StringWriter

inline fun <reified T : LdObject> T.deepCopy(): T {
    return json.decodeFromJsonElement<T>(json.encodeToJsonElement<T>(this))
}

inline fun <reified T : LdObject> T.toJsonDocument(): JsonDocument {
    return json.encodeToString<T>(this).byteInputStream().use {
        JsonDocument.of(it)
    }
}

inline fun <reified T : LdObject> T.toDataset(): RdfDataset {
    return JsonLd.toRdf(toJsonDocument()).options(defaultJsonLdOptions).get()
}

inline fun <reified T : LdObject> T.toNQuads(): String {
    val stringWriter = StringWriter()
    NQuadsWriter(stringWriter).write(toDataset())
    return stringWriter.toString()
}

inline fun <reified T : LdObject> T.normalize(): String {
    val rdfDataset = RdfNormalize.normalize(toDataset())
    val stringWriter = StringWriter()
    NQuadsWriter(stringWriter).write(rdfDataset)
    return stringWriter.toString()
}

inline fun <reified T> JsonDocument.toJsonLdObject(): T {
    return json.decodeFromString<T>(jsonContent.get().toString())
}

fun JsonDocument.fixBooleansAndNumbers() : JsonDocument {
        //TODO: quick and dirty workaround fixing the boolean/number issue of the titan library
        // fails if strings contain numbers or boolean values, e.g. "true" or "1223"
        return jsonContent.get().toString()
            .replace(Regex("\"(true|false|[-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?)\""), "$1").byteInputStream().use { JsonDocument.of ( it ) }
}


