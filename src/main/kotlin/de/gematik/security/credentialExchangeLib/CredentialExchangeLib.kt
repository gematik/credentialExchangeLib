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

package de.gematik.security.credentialExchangeLib

import de.gematik.security.credentialExchangeLib.connection.DidCommV2OverHttp.SecretResolverTransient
import org.didcommx.didcomm.secret.SecretResolverEditable

val credentialExchangeLib = CredentialExchangeLib()

class CredentialExchangeLib {
    var secretResolver : SecretResolverEditable = SecretResolverTransient()
        private set
    fun init(init: Builder.() -> Unit){
        Builder().apply{init()}.build()
    }

    inner class Builder internal constructor(){
        var secretResolver : SecretResolverEditable? = null
        fun build(){
            this@Builder.secretResolver?.let{this@CredentialExchangeLib.secretResolver = it}
        }
    }
}