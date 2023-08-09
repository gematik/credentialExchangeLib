package de.gematik.security.credentialExchangeLib

import org.junit.platform.suite.api.SelectClasses
import org.junit.platform.suite.api.Suite

@Suite
@SelectClasses(
    JsonLdTests::class,
    BbsProofTests::class,
    P256ProofTest::class,
    SerializerTests::class,
    ConnectionTests::class,
    ProtocolTests::class
)
class TestSuite