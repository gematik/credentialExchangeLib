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