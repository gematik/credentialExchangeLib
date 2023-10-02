package de.gematik.security.credentialExchangeLib.protocols

enum class GoalCode(val holderProtocol: ProtocolFactory<*>, val agentProtocol: ProtocolFactory<*>) {
    OFFER_CREDENDIAL(CredentialExchangeHolderProtocol, CredentialExchangeIssuerProtocol),
    REQUEST_CREDENTIAL(CredentialExchangeHolderProtocol, CredentialExchangeIssuerProtocol),
    REQUEST_PRESENTATION(PresentationExchangeHolderProtocol, PresentationExchangeVerifierProtocol),
    OFFER_PRESENTATION(PresentationExchangeHolderProtocol, PresentationExchangeVerifierProtocol)
}