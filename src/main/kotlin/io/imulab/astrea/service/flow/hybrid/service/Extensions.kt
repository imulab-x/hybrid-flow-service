package io.imulab.astrea.service.flow.hybrid.service

import io.imulab.astrea.sdk.oauth.token.strategy.AuthorizeCodeStrategy

fun AuthorizeCodeStrategy.enableServiceAware(serviceId: String): AuthorizeCodeStrategy {
    return ServiceAwareAuthorizeCodeStrategy(serviceId, this)
}