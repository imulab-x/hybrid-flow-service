package io.imulab.astrea.service.flow.hybrid.persistence

import com.fasterxml.jackson.annotation.JsonProperty
import io.imulab.astrea.sdk.client.VoidClient
import io.imulab.astrea.sdk.oauth.assertType
import io.imulab.astrea.sdk.oauth.error.InvalidGrant
import io.imulab.astrea.sdk.oauth.request.OAuthAuthorizeRequest
import io.imulab.astrea.sdk.oauth.request.OAuthRequest
import io.imulab.astrea.sdk.oauth.token.storage.AuthorizeCodeRepository
import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.imulab.astrea.sdk.oidc.request.OidcSession
import io.imulab.astrea.sdk.oidc.request.OidcSessionRepository
import io.vertx.core.json.Json
import io.vertx.kotlin.redis.delAwait
import io.vertx.kotlin.redis.getAwait
import io.vertx.kotlin.redis.setWithOptionsAwait
import io.vertx.redis.RedisClient
import io.vertx.redis.op.SetOptions
import java.time.Duration
import java.time.LocalDateTime
import java.time.ZoneOffset

/**
 * Redis implementation of [AuthorizeCodeRepository] and [OidcSessionRepository]. It uses an internal representation
 * [PersistenceForm] to save code sessions.
 *
 * This implementation uses a little hack to avoid implement both repositories individually. Because session data
 * in both repositories largely overlaps, this implementation does nothing when asked to perform
 * [OidcSessionRepository.createOidcSession] because it assumes [AuthorizeCodeRepository.createAuthorizeCodeSession]
 * is already invoked by a previous handler, and thus session is already created. Likewise, this implementation
 * does nothing when [AuthorizeCodeRepository.invalidateAuthorizeCodeSession] is invoked, because it assumes
 * [OidcSessionRepository.deleteOidcSession] will be invoked by a later handler. However, this assumption may be invalid
 * when the incoming request is not an OAuth only request, thus effectively skipping the later handler. In this case,
 * the handler caller should call [OidcSessionRepository.deleteOidcSession] explicitly just to be safe.
 */
class RedisAuthorizeCodeRepository(
    private val client: RedisClient,
    private val authorizeCodeLifespan: Duration
): AuthorizeCodeRepository, OidcSessionRepository {

    override suspend fun createAuthorizeCodeSession(code: String, request: OAuthRequest) {
        client.setWithOptionsAwait(
            code,
            Json.encode(PersistenceForm.fromRequest(request)),
            SetOptions().setEX(authorizeCodeLifespan.toMillis() / 1000)
        )
    }

    override suspend fun getAuthorizeCodeSession(code: String): OAuthRequest {
        val json = client.getAwait(code) ?: throw InvalidGrant.invalid()
        val decoded = Json.decodeValue(json, PersistenceForm::class.java)
        return decoded.toRequest()
    }

    override suspend fun invalidateAuthorizeCodeSession(code: String) {
        // do nothing because we will let the oidc handler invalidate.
    }

    override suspend fun createOidcSession(authorizeCode: String, session: OidcSession) {
        // do nothing because oauth handler already created a session.
    }

    override suspend fun getOidcSession(authorizeCode: String): OidcSession {
        return getAuthorizeCodeSession(authorizeCode).session.assertType()
    }

    override suspend fun deleteOidcSession(authorizeCode: String) {
        client.delAwait(authorizeCode)
    }

    class PersistenceForm {
        @JsonProperty("1") var id: String = ""
        @JsonProperty("2") var requestTime: Long = 0
        @JsonProperty("3") var clientId: String = ""
        @JsonProperty("4") var scopes: Set<String> = emptySet()
        @JsonProperty("5") var subject: String = ""
        @JsonProperty("6") var acrValues: List<String> = emptyList()
        @JsonProperty("7") var accessTokenClaims: Map<String, Any> = emptyMap()
        @JsonProperty("8") var idTokenClaims: Map<String, Any> = emptyMap()
        @JsonProperty("9") var authTime: Long = 0
        @JsonProperty("10") var nonce: String = ""
        @JsonProperty("11") var redirectUri: String = ""
        @JsonProperty("12") var obfuscatedSubject: String = ""

        fun toRequest(): OAuthRequest {
            return OidcAuthorizeRequest.Builder().also { b ->
                b.client = IdOnlyClient(clientId)
                b.nonce = nonce
                b.redirectUri = redirectUri
                b.session = OidcSession().also { s ->
                    s.subject = subject
                    s.obfuscatedSubject = obfuscatedSubject
                    s.acrValues.addAll(acrValues)
                    s.authTime = LocalDateTime.ofEpochSecond(authTime, 0, ZoneOffset.UTC)
                    s.nonce = nonce
                    s.accessTokenClaims.putAll(accessTokenClaims)
                    s.idTokenClaims.putAll(idTokenClaims)
                    s.grantedScopes.addAll(scopes)
                }
            }.build().also { r ->
                r.id = id
                r.requestTime = LocalDateTime.ofEpochSecond(requestTime, 0, ZoneOffset.UTC)
            }
        }

        companion object {
            fun fromRequest(req: OAuthRequest) : PersistenceForm {
                return PersistenceForm().apply {
                    id = req.id
                    requestTime = req.requestTime.toEpochSecond(ZoneOffset.UTC)
                    clientId = req.client.id
                    scopes = req.session.grantedScopes
                    subject = req.session.subject
                    obfuscatedSubject = req.session.assertType<OidcSession>().obfuscatedSubject
                    accessTokenClaims = req.session.accessTokenClaims
                    acrValues = req.session.assertType<OidcSession>().acrValues
                    idTokenClaims = req.session.assertType<OidcSession>().idTokenClaims
                    authTime = req.session.assertType<OidcSession>().authTime?.toEpochSecond(ZoneOffset.UTC) ?: 0
                    nonce = req.session.assertType<OidcSession>().nonce
                    redirectUri = when (req) {
                        is OAuthAuthorizeRequest -> req.client.determineRedirectUri(req.redirectUri)
                        else -> ""
                    }
                }
            }
        }
    }

    /**
     * Client implementation that only has (or only need) its id.
     */
    class IdOnlyClient(override val id: String) : VoidClient()
}