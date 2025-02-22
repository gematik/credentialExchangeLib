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

import bbs.signatures.ProofMessage
import com.apicatalog.jsonld.JsonLd
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.jsonld.document.RdfDocument
import de.gematik.security.credentialExchangeLib.crypto.*
import de.gematik.security.credentialExchangeLib.defaultJsonLdOptions
import de.gematik.security.credentialExchangeLib.extensions.*
import de.gematik.security.credentialExchangeLib.json
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.time.ZonedDateTime
import java.util.*
import kotlin.random.Random

@Serializable
class LdProof : LdObject {
    constructor(
        id: String? = null,
        atContext: List<URI> = DEFAULT_JSONLD_CONTEXTS,
        type: List<String>,
        creator: URI? = null,
        created: ZonedDateTime,
        domain: String? = null,
        challenge: String? = null,
        nonce: String? = null,
        proofPurpose: ProofPurpose,
        verificationMethod: URI,
        proofValue: String? = null
    ) : super(id, atContext, type){
        _creator = creator?.toString()
        _created = created.toIsoInstantString()
        this.domain = domain
        this.challenge = challenge
        this.nonce = nonce
        this.proofPurpose = proofPurpose
        _verificationMethod = verificationMethod.toString()
        this.proofValue = proofValue
    }

    @SerialName("creator") private var _creator: String?
    val creator
        get() = _creator?.let { URI.create(it)}
    @SerialName("created") private val _created: String
    val domain: String?
    val challenge: String?
    var nonce: String?
    val proofPurpose: ProofPurpose
    @SerialName("verificationMethod") private val _verificationMethod: String
    val verificationMethod
        get() = URI.create(_verificationMethod)
    var proofValue: String?

    companion object : Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://w3id.org/security/bbs/v1")
        )
        override val DEFAULT_JSONLD_TYPES = emptyList<String>()
    }

    inline fun <reified T> sign(jsonLdObject: T, privateKey: ByteArray) where T : LdObject, T : Verifiable {
        check(proofValue == null) { "proof already contains proof value" }
        check(jsonLdObject.proof == null) { "jsonLdObject already signed" }
        val signer = type.firstOrNull()?.let {
            runCatching {
                CryptoRegistry.getSigner(
                    ProofType.valueOf(it),
                    KeyPair(
                        privateKey,
                        verificationMethod.toPublicKey()
                    )
                )
            }.getOrNull()
        }
        check(
            signer != null
        ) { "no signer registered for proof type: ${type.firstOrNull()}" }
        val statements = listOf(
            normalize().trim().split('\n'),
            jsonLdObject.normalize<T>().trim().split('\n')
        ).flatMap { it.map { it.toByteArray() } }
        proofValue = String(Base64.getEncoder().encode(signer.sign(statements)))
    }

    inline suspend fun <reified T> asyncSign(jsonLdObject: T, privateKey: ByteArray, context: Any) where T : LdObject, T : Verifiable {
        check(proofValue == null) { "proof already contains proof value" }
        check(jsonLdObject.proof == null) { "jsonLdObject already signed" }
        val signer = type.firstOrNull()?.let {
            runCatching {
                CryptoRegistry.getSigner(
                    ProofType.valueOf(it),
                    KeyPair(
                        privateKey,
                        verificationMethod.toPublicKey()
                    )
                )
            }.getOrNull()
        } as? AsyncSigner
        check(
            signer != null
        ) { "no async signer registered for proof type: ${type.firstOrNull()}" }
        val statements = listOf(
            normalize().trim().split('\n'),
            jsonLdObject.normalize<T>().trim().split('\n')
        ).flatMap { it.map { it.toByteArray() } }
        proofValue = String(Base64.getEncoder().encode(signer.asyncSign(statements, context)))
    }

    inline fun <reified T> verify(
        jsonLdObject: T
    ): Boolean where T : LdObject, T : Verifiable {
        val singleType = type.firstOrNull() ?: return false
        val verifier =
            runCatching {
                CryptoRegistry.getVerifier(
                    ProofType.valueOf(singleType),
                    verificationMethod.toPublicKey()
                )
            }.getOrNull()
        return when (verifier) {
            is ProofVerifier -> {
                if(ProofType.valueOf(singleType).isProof) {
                    (jsonLdObject as? Credential)?.let { verifyProof(it, verifier) } ?: false
                }else{
                    verify(jsonLdObject, verifier)
                }
            }
            is Verifier -> verify(jsonLdObject, verifier)
            else -> false
        }
    }

    fun deriveProof(credential: Credential, frame: Credential): Credential {

        // 0. check if signature is suitable for deriving proof
        val signer = type.firstOrNull()?.let {
            runCatching {
                CryptoRegistry.getSigner(
                    ProofType.valueOf(it),
                    KeyPair(publicKey = verificationMethod.toPublicKey())
                )
            }.getOrNull()
        } as? Proofer
        check(
            signer != null
        ) { "proof type doesn't support proof derivation" }

        // 1. frame input document
        val credentialWithoutProof = credential.deepCopy().apply { proof = null }
        // 1.1. normalize input document to rdf string
        val normalizedCredential = credentialWithoutProof.normalize().trim()
        // 1.2. convert internal blank node identifiers to uniform black node identifiers (urn:bnid)
        val normalizedTransformedCredential = normalizedCredential.replace(Regex("_:c14n[0-9]*"), "<urn:bnid:$0>")
        // 1.3. create expanded input document from rdf string
        val expandedInputDocumentWrongBoolean = normalizedTransformedCredential.byteInputStream(Charsets.ISO_8859_1).use {
            JsonDocument.of(
                JsonLd.fromRdf(
                    RdfDocument.of(it)
                ).options(defaultJsonLdOptions).get()
            )
        }
        val expandedInputDocument = expandedInputDocumentWrongBoolean.fixBooleansAndNumbers()
        // 1.4. frame
        val framedCredential = json.decodeFromString<Credential>(
            JsonLd.frame(expandedInputDocument, frame.toJsonDocument()).options(defaultJsonLdOptions).get().toString()
        )
        // 1.5. normalize framed credential
        val normalizedFramedCredential = framedCredential.normalize().trim()
        // 1.6. revert blank node identifier to internal blank node identifiers
        val normalizedTransformedFramedCredential = normalizedFramedCredential.replace(Regex("<urn:bnid:(_:c14n[0-9]*)>"), "$1")
        // 2. prepare list of proof messages
        // 2.1. init list of ProofMessage with messages from LdProof without proof value
        val newLdProof = deepCopy().apply { proofValue = null }
        val proofMessages = newLdProof.normalize().trim().split('\n').map {
            ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_REVEALED, it.toByteArray(), null)
        }.toMutableList()
        // 2.2. add proof messages from credential
        val framedCredentialMessages = normalizedTransformedFramedCredential.split('\n')
        var j = 0
        normalizedCredential.split('\n').forEach {
            val type = if (j < framedCredentialMessages.size && it == framedCredentialMessages.get(j)) {
                j++
                ProofMessage.PROOF_MESSAGE_TYPE_REVEALED
            } else {
                ProofMessage.PROOF_MESSAGE_TYPE_HIDDEN_PROOF_SPECIFIC_BLINDING
            }
            proofMessages.add(ProofMessage(type, it.toByteArray(), null))
        }
        // 3. calculate signature
        val nonce = Random.nextBytes(32)
        val signature = signer.deriveProof(Base64.getDecoder().decode(proofValue), nonce, proofMessages)
        // 4. complete new proof, add to new credential and return
        return framedCredential.apply {
            proof = listOf(newLdProof.apply {
                type = listOf(signer.derivedProofType.name)
                proofValue = Base64.getEncoder().encodeToString(signature)
                this.nonce = Base64.getEncoder().encodeToString(nonce)
            })
        }
    }

    inline fun <reified T> verify(
        jsonLdObject: T, verifier: Verifier
    ): Boolean where T : LdObject, T : Verifiable {
        val ldProofWithoutProofValue = deepCopy().apply { proofValue = null }
        val jsonLdObjectWithoutProof = jsonLdObject.deepCopy<T>().apply { proof = null }
        val statements = listOf(
            ldProofWithoutProofValue.normalize().trim().split('\n'),
            jsonLdObjectWithoutProof.normalize<T>().trim().split('\n')
        ).flatMap { it.map { it.toByteArray() } }
        return verifier.verify(statements, Base64.getDecoder().decode(proofValue))
    }

    fun verifyProof(credential: Credential, verifier: ProofVerifier): Boolean {

        // 1. prepare original proof
        val ldProofWithoutProofValue = deepCopy().apply {
            // 1.1 remove proof value
            proofValue = null
            //1.2 remove nonce
            nonce = null
            //1.3 set original proof type
            type = listOf(verifier.originalProofType.name)
        }
        // 2. prepare credential
        val credentialWithoutProof = credential.deepCopy().apply { proof = null }
        // 3. normalize credential and ldproof and revert uri blank node identifier (urn:bnid) back into internal blank node identifiers
        val statements = listOf(
            ldProofWithoutProofValue.normalize().trim().replace(Regex("<urn:bnid:(_:c14n[0-9]*)>"), "$1").split('\n'),
            credentialWithoutProof.normalize().trim().replace(Regex("<urn:bnid:(_:c14n[0-9]*)>"), "$1").split('\n')
        ).flatMap { it.map { it.toByteArray() } }
        // 4. get verifier and verify revealed messages
        return verifier.verifyProof(
            statements,
            Base64.getDecoder().decode(proofValue),
            Base64.getDecoder().decode(nonce)
        )
    }


}