package io.imulab.astrea.service.flow.hybrid.persistence

import io.imulab.astrea.sdk.commons.doNotCall
import io.imulab.astrea.sdk.oauth.request.OAuthRequest
import io.imulab.astrea.sdk.oauth.token.storage.AccessTokenRepository

/**
 * NoOp implementation of [AccessTokenRepository]. Since we are implementing JWT bearer token type. There is no need
 * to save state for introspection.
 */
object NoOpAccessTokenRepository : AccessTokenRepository {
    override suspend fun createAccessTokenSession(token: String, request: OAuthRequest) {}  // no-op
    override suspend fun getAccessTokenSession(token: String): OAuthRequest = doNotCall()
    override suspend fun deleteAccessTokenSession(token: String) {}  // no-op
    override suspend fun deleteAccessTokenAssociatedWithRequest(requestId: String) {}  // no-op
}