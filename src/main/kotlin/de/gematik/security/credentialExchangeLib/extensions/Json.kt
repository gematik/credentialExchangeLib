package de.gematik.security.mobilewallet.extensions

import foundation.identity.jsonld.JsonLDUtils
import java.util.*

fun kotlinx.serialization.json.JsonObject.toString(indentSpaces: Int) : String {
    return org.json.JSONObject(toString()).toString(indentSpaces)
}

fun jakarta.json.JsonObject.toString(indentSpaces: Int) : String {
    return org.json.JSONObject(toString()).toString(indentSpaces)
}

fun Date.toJsonLdString() : String {
    return JsonLDUtils.dateToString(this)
}

fun String.toDate() : Date {
    return JsonLDUtils.stringToDate(this)
}
