package de.gematik.security.credentialExchangeLib

import org.junit.platform.suite.api.SelectClasses
import org.junit.platform.suite.api.Suite

@Suite
@SelectClasses(
    JsonLdTests::class,
    ProofTests::class,
    SerializerTests::class,
    ConnectionTests::class
)
class TestSuite