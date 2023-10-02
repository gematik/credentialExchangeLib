package de.gematik.security.credentialExchangeLib.connection.DidCommV2OverHttp

import org.didcommx.didcomm.secret.Secret
import org.didcommx.didcomm.secret.SecretResolverEditable
import java.util.*

class SecretResolverTransient : SecretResolverEditable {
    private val secrets = mutableMapOf<String, Secret>()

    override fun addKey(secret: Secret) {
        secrets.put(secret.kid, secret)
    }

    override fun getKids(): List<String> =
        secrets.keys.toList()

    override fun findKey(kid: String): Optional<Secret> =
        Optional.ofNullable(secrets.get(kid))

    override fun findKeys(kids: List<String>): Set<String> =
        kids.intersect(secrets.keys)

}