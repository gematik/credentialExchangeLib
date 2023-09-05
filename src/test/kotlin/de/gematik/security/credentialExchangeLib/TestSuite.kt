package de.gematik.security.credentialExchangeLib

import org.junit.platform.suite.api.SelectClasses
import org.junit.platform.suite.api.Suite

@Suite
@SelectClasses(
    JsonLdTests::class,
    BbsProofTests::class,
    EcdsaProofTest::class,
    SerializerTests::class,
    ConnectionTests::class,
    ProtocolTests::class,
    AcapyInteropTest::class,
    DilithiumProofTest::class
)
class TestSuite