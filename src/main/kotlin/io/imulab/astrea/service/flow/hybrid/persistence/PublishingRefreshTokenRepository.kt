package io.imulab.astrea.service.flow.hybrid.persistence

import io.imulab.astrea.sdk.commons.doNotCall
import io.imulab.astrea.sdk.event.RefreshTokenEvents
import io.imulab.astrea.sdk.oauth.assertType
import io.imulab.astrea.sdk.oauth.request.OAuthRequest
import io.imulab.astrea.sdk.oauth.token.storage.RefreshTokenRepository
import io.vertx.core.Vertx

/**
 * Message publishing implementation of [RefreshTokenRepository]. When a refresh token is created, this repository
 * should broadcast relevant information which should be picked by a refresh token service.
 */
class PublishingRefreshTokenRepository(private val vertx: Vertx) : RefreshTokenRepository {
    override suspend fun createRefreshTokenSession(token: String, request: OAuthRequest) {
        vertx.eventBus().publish(
            RefreshTokenEvents.refreshTokenCreatedEvent,
            RefreshTokenEvents.refreshTokenCreated(token, request.assertType())
        )
    }
    override suspend fun getRefreshTokenSession(token: String): OAuthRequest = doNotCall()
    override suspend fun deleteRefreshTokenSession(token: String) = doNotCall()
    override suspend fun deleteRefreshTokenAssociatedWithRequest(requestId: String) = doNotCall()
}