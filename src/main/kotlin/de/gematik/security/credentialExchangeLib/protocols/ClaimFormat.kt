package de.gematik.security.credentialExchangeLib.protocols

import kotlinx.serialization.SerialName

enum class ClaimFormat {
    @SerialName("jwt_vc") JWT_VC,
    @SerialName("jwt_vp") JWT_VP,
    @SerialName("ldp_vc") LDP_VC,
    @SerialName("ldp_vp") LDP_VP
}