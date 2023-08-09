package de.gematik.security.credentialExchangeLib.crypto.ecdsa

import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters

val secp256r1DomainParameters = SECNamedCurves.getByName("secp256r1").let { ECDomainParameters(it.curve, it.g, it.n, it.h, it.seed) }
