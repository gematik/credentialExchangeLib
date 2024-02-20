package de.gematik.security.credentialExchangeLib

import org.junit.platform.suite.api.SelectClasses
import org.junit.platform.suite.api.Suite

@Suite
@SelectClasses(
    JsonLdTests::class,
    BbsProofTests::class,
    EcdsaProofTest::class,
    Ed25519ProofTest::class,
    DilithiumProofTest::class,
    SerializerTests::class,
    WsConnectionTests::class,
    DidCommConnectionTests::class,
    ProtocolTests::class,
    AcapyInteropTest::class,
)
class TestSuite