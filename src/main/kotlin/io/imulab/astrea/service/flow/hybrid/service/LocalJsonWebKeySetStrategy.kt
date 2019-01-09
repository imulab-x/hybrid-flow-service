package io.imulab.astrea.service.flow.hybrid.service

import io.imulab.astrea.sdk.commons.doNotCall
import io.imulab.astrea.sdk.oidc.jwk.JsonWebKeySetRepository
import io.imulab.astrea.sdk.oidc.jwk.JsonWebKeySetStrategy
import io.imulab.astrea.sdk.oidc.spi.HttpResponse
import io.imulab.astrea.sdk.oidc.spi.SimpleHttpClient
import org.jose4j.jwk.JsonWebKeySet

/**
 * Extension to [JsonWebKeySetStrategy] to resolve all keys locally. Hence, client and repository are not really needed.
 */
class LocalJsonWebKeySetStrategy(serverJwks: JsonWebKeySet) : JsonWebKeySetStrategy(
    httpClient = object : SimpleHttpClient {
        override suspend fun get(url: String): HttpResponse = doNotCall()
    },
    jsonWebKeySetRepository = object : JsonWebKeySetRepository {
        override suspend fun getServerJsonWebKeySet(): JsonWebKeySet = serverJwks
        override suspend fun getClientJsonWebKeySet(jwksUri: String): JsonWebKeySet? = null
        override suspend fun writeClientJsonWebKeySet(jwksUri: String, keySet: JsonWebKeySet) {}
    }
)