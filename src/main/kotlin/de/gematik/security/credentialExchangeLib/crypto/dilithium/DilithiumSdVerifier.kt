package de.gematik.security.credentialExchangeLib.crypto.dilithium

import de.gematik.security.credentialExchangeLib.crypto.ProofType
import de.gematik.security.credentialExchangeLib.crypto.ProofVerifier
import de.gematik.security.credentialExchangeLib.crypto.Verifier
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters
import java.nio.ByteBuffer
import java.security.MessageDigest

abstract class DilithiumSdVerifier(publicKey: ByteArray, val params: DilithiumParameters, val signatureSize: Int, override val originalProofType: ProofType) :
    Verifier, ProofVerifier {

    final override val publicKey: ByteArray
    val verifier = org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner()

    init {
        val publicKeyParameters = params.getPublicKeyParameters(publicKey)
        verifier.init(
            false, DilithiumPublicKeyParameters(
                params,
                publicKeyParameters.rho,
                publicKeyParameters.t1
            )
        )
        this.publicKey = publicKey
    }

    override fun verify(content: List<ByteArray>, signature: ByteArray): Boolean {
        return runCatching {
            check(signature.size == signatureSize + 16) { "signature of length ${signatureSize + 16} expected, but was ${signature.size}" }
            // 1. retrieve salt and signature of hash
            // signature = salt+signatureOfHash
            val salt = signature.copyOfRange(0, 16)
            val signatureOfHash = signature.copyOfRange(16, signature.size)
            // 2. calculate salted hashes
            val saltedHashes = content.getSaltedHashes(salt)
            // 3. calculate hash of hashes
            val hash = MessageDigest.getInstance("SHA-256").apply {
                saltedHashes.forEach {
                    update(it)
                }
            }.digest()
            // 4. verify signature of calculated hash
            verifier.verifySignature(
                hash,
                signatureOfHash
            )
        }.getOrElse { false }
    }

    override fun verifyProof(content: List<ByteArray>, proof: ByteArray, nonce: ByteArray): Boolean {
        return runCatching {
            // 1. retrieve info from proof
            // proof = lengthOfInfoBlock + infoBlock + salt + signatureOfHash
            val byteBuffer = ByteBuffer.wrap(proof)
            val lengthOfBlock = byteBuffer.getInt()
            val infoBlock = ByteBuffer.wrap(ByteArray(lengthOfBlock).apply { byteBuffer.get(this) })
            val salt = ByteArray(16).apply { byteBuffer.get(this) }
            // 2. calculate salted hashes by processing info block
            val signatureOfHash = ByteArray(signatureSize).apply { byteBuffer.get(this) }
            val saltedHashes = emptyList<ByteArray>().toMutableList()
            var indexContent = 0
            var s = salt
            while (true) {
                val numberOfRevealedMessages = infoBlock.getShort()
                saltedHashes.addAll(
                    content.subList(indexContent, indexContent + numberOfRevealedMessages).getSaltedHashes(s)
                )
                indexContent += numberOfRevealedMessages
                if (!infoBlock.hasRemaining()) break
                ByteArray(32).apply { infoBlock.get(this) }.let{
                    saltedHashes.add(it)
                    s = it
                }
            }
            check(content.size == indexContent) { "inconsistent proof data: ${content.size} != ${indexContent}" }
            // 3. calculate hash of hashes
            val hash = MessageDigest.getInstance("SHA-256").apply {
                saltedHashes.forEach {
                    update(it)
                }
            }.digest()
            // 4. verify signature of calculated hash
            verifier.verifySignature(
                hash,
                signatureOfHash
            )
        }.getOrElse { false }
    }
}

class Dilithium2SdVerifier(publicKey: ByteArray) : DilithiumSdVerifier(publicKey, DilithiumParameters.dilithium2, 2420, ProofType.Dilithium2SdSignature2023)
class Dilithium2SdAesVerifier(publicKey: ByteArray) :
    DilithiumSdVerifier(publicKey, DilithiumParameters.dilithium2_aes, 2420, ProofType.Dilithium2SdSignature2023)

class Dilithium3SdVerifier(publicKey: ByteArray) : DilithiumSdVerifier(publicKey, DilithiumParameters.dilithium3, 3293, ProofType.Dilithium3SdSignature2023)
class Dilithium3SdAesVerifier(publicKey: ByteArray) :
    DilithiumSdVerifier(publicKey, DilithiumParameters.dilithium3_aes, 3293, ProofType.Dilithium3SdSignature2023)

class Dilithium5SdVerifier(publicKey: ByteArray) : DilithiumSdVerifier(publicKey, DilithiumParameters.dilithium5, 4595, ProofType.Dilithium5SdSignature2023)
class Dilithium5SdAesVerifier(publicKey: ByteArray) :
    DilithiumSdVerifier(publicKey, DilithiumParameters.dilithium5_aes, 4595, ProofType.Dilithium5SdSignature2023)
