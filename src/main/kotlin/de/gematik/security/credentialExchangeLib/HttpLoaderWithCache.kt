import com.apicatalog.jsonld.document.Document
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.jsonld.http.DefaultHttpClient
import com.apicatalog.jsonld.loader.DocumentLoaderOptions
import com.apicatalog.jsonld.loader.HttpLoader
import java.net.URI

object HttpLoaderWithCache : HttpLoader(DefaultHttpClient.defaultInstance()) {
    private val staticCache = mapOf(
        "https://gematik.de/vsd/v1" to getContext("/context/vsd_v1.jsonld"),
        "https://w3id.org/security/v2" to getContext("/context/security_v2.jsonld"),
        "https://www.w3.org/2018/credentials/v1" to getContext("/context/2018_credentials_v1.jsonld"),
        "https://w3id.org/vaccination/v1" to getContext("/context/vaccination_v1_modified.jsonld"),
        "https://w3id.org/security/bbs/v1" to getContext("/context/security_bbs_v1.jsonld"),
        "https://identity.foundation/presentation-exchange/submission/v1/" to getContext("/context/submission_v1.jsonld"),
        "https://gematik.de/credential-exchange/v1/" to getContext("/context/credentialexchange_v1.jsonld")
    )

    override fun loadDocument(uri: URI?, options: DocumentLoaderOptions?): Document {
        return staticCache.get(uri.toString())?:super.loadDocument(uri, options)
    }

    private fun getContext(name: String) : JsonDocument{
        return JsonDocument.of(javaClass.getResourceAsStream(name))
    }
}