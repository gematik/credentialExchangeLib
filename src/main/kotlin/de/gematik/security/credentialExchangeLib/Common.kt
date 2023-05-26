package de.gematik.security.credentialExchangeLib

import HttpLoaderWithCache
import com.apicatalog.jsonld.JsonLdOptions
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json

@OptIn(ExperimentalSerializationApi::class)
val json = Json { prettyPrint = true; explicitNulls=false }

val defaultJsonLdOptions = JsonLdOptions().apply {
    isOrdered = true
    documentLoader = HttpLoaderWithCache
}





