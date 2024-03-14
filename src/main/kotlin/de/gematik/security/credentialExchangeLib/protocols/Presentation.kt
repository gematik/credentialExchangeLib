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
import kotlinx.serialization.Serializable
import java.net.URI

@Serializable
class Presentation : LdObject, Verifiable {
    constructor(
        id: String? = null,
        atContext: List<URI> = DEFAULT_JSONLD_CONTEXTS,
        type: List<String> = DEFAULT_JSONLD_TYPES,
        presentationSubmission: PresentationSubmission,
        verifiableCredential: List<Credential>
    ) : super(id, atContext, type) {
        this.presentationSubmission = presentationSubmission
        this.verifiableCredential = verifiableCredential
    }

    val presentationSubmission: PresentationSubmission
    val verifiableCredential: List<Credential>
    override var proof: @Serializable(with = UnwrappingSingleValueJsonArrays::class) List<LdProof>? = null

    companion object : LdObject.Defaults() {
        override val DEFAULT_JSONLD_CONTEXTS = listOf(
            URI("https://www.w3.org/2018/credentials/v1")
        )
        override val DEFAULT_JSONLD_TYPES = listOf(
            "VerifiablePresentation"
        )
    }

    override fun sign(ldProof: LdProof, privateKey: ByteArray) {
        ldProof.sign(this, privateKey)
        proof = listOf(ldProof)
    }

    suspend fun asyncSign(ldProof: LdProof, privateKey: ByteArray, context: Any) {
        ldProof.asyncSign(this, privateKey, context)
        proof = listOf(ldProof)
    }

    override fun verify(): Boolean {
        val singleProof = proof?.firstOrNull()
        check(singleProof != null) { "presentation doesn't contain a proof for verification" }
        check(proof?.size == 1) { "verfication of multi signature not supported yet" }
        return singleProof.verify(this)
    }

}

