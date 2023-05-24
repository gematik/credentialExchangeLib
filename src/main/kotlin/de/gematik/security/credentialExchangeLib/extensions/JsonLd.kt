package de.gematik.security.credentialExchangeLib.extensions

import com.apicatalog.jsonld.JsonLd
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.rdf.RdfDataset
import com.apicatalog.rdf.io.nquad.NQuadsWriter
import de.gematik.security.credentialExchangeLib.crypto.BbsPlusSigner
import de.gematik.security.credentialExchangeLib.json
import de.gematik.security.credentialExchangeLib.types.LdObject
import de.gematik.security.credentialExchangeLib.types.LdProof
import de.gematik.security.credentialExchangeLib.types.ProofPurpose
import de.gematik.security.credentialExchangeLib.types.Verifiable
import de.gematik.security.credentialExchangeLib.verificationMethodtoBls12381G2PublicKey
import de.gematik.security.credentialExchangeLib.crypto.BbsPlusVerifier
import de.gematik.security.credentialExchangeLib.crypto.Signer
import de.gematik.security.credentialExchangeLib.crypto.Verifier
import io.setl.rdf.normalization.RdfNormalize
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import java.io.StringWriter
import java.security.GeneralSecurityException
import java.util.*
import kotlin.reflect.KClass

inline fun <reified T : LdObject> T.deepCopy(): T {
    return json.decodeFromJsonElement<T>(json.encodeToJsonElement<T>(this))
}

inline fun <reified T : LdObject> T.toJsonDocument(): JsonDocument {
    return json.encodeToString<T>(this).byteInputStream().use {
        JsonDocument.of(it)
    }
}

inline fun <reified T : LdObject> T.toDataset(): RdfDataset {
    return JsonLd.toRdf(toJsonDocument()).get()
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

inline fun <reified T> LdProof.sign(jsonLdObject: T, signer: Signer) where T : LdObject, T : Verifiable {
    check(proofValue == null) { "proof already contains proof value" }
    check(jsonLdObject.proof == null) {"jsonLdObject already signed"}
    val statements = listOf(
        normalize().trim().split('\n'),
        jsonLdObject.normalize<T>().trim().split('\n')
    ).flatMap { it.map { it.toByteArray() } }
    proofValue = String(Base64.getEncoder().encode(signer.sign(statements)))
}

inline fun <reified T> LdProof.verify(
    jsonLdObject: T
): Boolean where T : LdObject, T : Verifiable {
    val ldProofWithoutProofValue = deepCopy().apply { proofValue = null }
    val jsonLdObjectWithoutProof = jsonLdObject.deepCopy<T>().apply { proof = null }
    val statements = listOf(
        ldProofWithoutProofValue.normalize().trim().split('\n'),
        jsonLdObjectWithoutProof.normalize<T>().trim().split('\n')
    ).flatMap { it.map { it.toByteArray() } }
    check(type!=null){"type required to sign link data proof"}
    val verifier = when{
        type.contains("https://w3id.org/security#BbsBlsSignature2020") -> BbsPlusVerifier(verificationMethod.verificationMethodtoBls12381G2PublicKey())
        else -> throw GeneralSecurityException("proof type not supported")
    }
    return verifier.verify(statements, Base64.getDecoder().decode(proofValue))
}



