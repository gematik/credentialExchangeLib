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

package de.gematik.security.credentialExchangeLib.extensions

import com.apicatalog.jsonld.JsonLd
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.rdf.RdfDataset
import com.apicatalog.rdf.io.nquad.NQuadsWriter
import de.gematik.security.credentialExchangeLib.defaultJsonLdOptions
import de.gematik.security.credentialExchangeLib.json
import de.gematik.security.credentialExchangeLib.protocols.JsonLdObject
import de.gematik.security.credentialExchangeLib.protocols.LdObject
import io.setl.rdf.normalization.RdfNormalize
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
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

inline fun <reified T : LdObject> T.toJsonLdObject(): JsonLdObject {
    return JsonLdObject(json.encodeToJsonElement<T>(this).jsonObject.toMap())
}

inline fun <reified T : LdObject> JsonLdObject.toObject(): T {
    return json.decodeFromJsonElement<T>(jsonContent)
}

fun JsonDocument.fixBooleansAndNumbers() : JsonDocument {
        // quick and dirty workaround fixing the boolean/number issue of the titan library
        // if you use this workaround make sure that
        // no types http://www.w3.org/2001/XMLSchema#* are defined for json booleans and numbers
        return jsonContent.get().toString()
            .replace(
                Regex("\"(true|false|[-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?)\",\"@type\":\"http://www.w3.org/2001/XMLSchema#[^\"]*\""),
                "$1")
            .byteInputStream().use { JsonDocument.of ( it ) }
}


