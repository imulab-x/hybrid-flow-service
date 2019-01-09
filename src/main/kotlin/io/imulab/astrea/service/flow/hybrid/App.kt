package io.imulab.astrea.service.flow.hybrid

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import io.grpc.ManagedChannelBuilder
import io.imulab.astrea.sdk.discovery.RemoteDiscoveryService
import io.imulab.astrea.sdk.discovery.SampleDiscovery
import io.imulab.astrea.sdk.oauth.handler.OAuthAuthorizeCodeHandler
import io.imulab.astrea.sdk.oauth.handler.helper.AccessTokenHelper
import io.imulab.astrea.sdk.oauth.handler.helper.RefreshTokenHelper
import io.imulab.astrea.sdk.oauth.reserved.AuthenticationMethod
import io.imulab.astrea.sdk.oauth.token.JwtSigningAlgorithm
import io.imulab.astrea.sdk.oauth.token.storage.RefreshTokenRepository
import io.imulab.astrea.sdk.oauth.token.strategy.*
import io.imulab.astrea.sdk.oauth.validation.*
import io.imulab.astrea.sdk.oidc.discovery.Discovery
import io.imulab.astrea.sdk.oidc.discovery.OidcContext
import io.imulab.astrea.sdk.oidc.handler.OidcAuthorizeCodeHandler
import io.imulab.astrea.sdk.oidc.handler.OidcHybridHandler
import io.imulab.astrea.sdk.oidc.token.IdTokenStrategy
import io.imulab.astrea.sdk.oidc.token.JwxIdTokenStrategy
import io.imulab.astrea.sdk.oidc.validation.NonceValidator
import io.imulab.astrea.sdk.oidc.validation.OidcResponseTypeValidator
import io.imulab.astrea.service.flow.hybrid.persistence.NoOpAccessTokenRepository
import io.imulab.astrea.service.flow.hybrid.persistence.PublishingRefreshTokenRepository
import io.imulab.astrea.service.flow.hybrid.persistence.RedisAuthorizeCodeRepository
import io.imulab.astrea.service.flow.hybrid.service.*
import io.vertx.core.Vertx
import io.vertx.ext.healthchecks.HealthCheckHandler
import io.vertx.ext.healthchecks.Status
import io.vertx.redis.RedisClient
import io.vertx.redis.RedisOptions
import kotlinx.coroutines.runBlocking
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.keys.AesKey
import org.kodein.di.Kodein
import org.kodein.di.generic.bind
import org.kodein.di.generic.eagerSingleton
import org.kodein.di.generic.instance
import org.kodein.di.generic.singleton
import org.slf4j.LoggerFactory
import java.time.Duration
import java.util.*

private val logger = LoggerFactory.getLogger("io.imulab.astrea.service.flow.hybrid.AppKt")

fun main(args: Array<String>) {
    val vertx = Vertx.vertx()
    val config = ConfigFactory.load()
    val app = App(vertx, config).bootstrap()

    val grpcApi by app.instance<GrpcVerticle>()
    vertx.deployVerticle(grpcApi) { ar ->
        if (ar.succeeded()) {
            logger.info("Hybrid flow service successfully deployed with id {}", ar.result())
        } else {
            logger.error("Hybrid flow service failed to deploy.", ar.cause())
        }
    }

    val healthApi by app.instance<HealthVerticle>()
    vertx.deployVerticle(healthApi) { ar ->
        if (ar.succeeded()) {
            logger.info("Hybrid flow service health information available.")
        } else {
            logger.error("Hybrid flow service health information unavailable.", ar.cause())
        }
    }
}

@Suppress("MemberVisibilityCanBePrivate")
open class App(vertx: Vertx, config: Config) {
    open fun bootstrap() = Kodein {
        importOnce(discovery)
        importOnce(persistence)
        importOnce(app)
    }

    val discovery = Kodein.Module("discovery") {
        bind<Discovery>() with eagerSingleton {
            val channel = ManagedChannelBuilder.forAddress(
                config.getString("discovery.host"),
                config.getInt("discovery.port")
            ).enableRetry().maxRetryAttempts(10).usePlaintext().build()

            if (config.getBoolean("discovery.useSample")) {
                logger.info("Using default discovery instead of remote.")
                SampleDiscovery.default()
            } else {
                runBlocking {
                    RemoteDiscoveryService(channel).getDiscovery()
                }
            }
        }
    }

    val persistence = Kodein.Module("persistence") {
        bind<RedisClient>() with singleton {
            RedisClient.create(vertx, RedisOptions().apply {
                host = config.getString("redis.host")
                port = config.getInt("redis.port")
                select = config.getInt("redis.db")
            })
        }

        bind<RedisAuthorizeCodeRepository>() with singleton {
            RedisAuthorizeCodeRepository(
                instance(),
                instance<ServiceContext>().authorizeCodeLifespan
            )
        }

        bind<RefreshTokenRepository>() with singleton { PublishingRefreshTokenRepository(vertx) }
    }

    val app = Kodein.Module("app") {
        bind<ServiceContext>() with singleton { ServiceContext(config, instance()) }

        bind<AuthorizeCodeStrategy>() with singleton {
            HmacSha2AuthorizeCodeStrategy(
                instance<ServiceContext>().authorizeCodeKey,
                JwtSigningAlgorithm.HS256
            ).enableServiceAware(config.getString("service.id"))
        }

        bind<AccessTokenStrategy>() with singleton {
            JwtAccessTokenStrategy(
                instance<ServiceContext>(),
                JwtSigningAlgorithm.RS256,
                instance<ServiceContext>().masterJsonWebKeySet
            )
        }

        bind<RefreshTokenStrategy>() with singleton {
            HmacSha2RefreshTokenStrategy(
                instance<ServiceContext>().refreshTokenKey,
                JwtSigningAlgorithm.HS256
            )
        }

        bind<IdTokenStrategy>() with singleton {
            JwxIdTokenStrategy(
                instance<ServiceContext>(),
                LocalJsonWebKeySetStrategy(instance<ServiceContext>().masterJsonWebKeySet)
            )
        }

        bind<OAuthAuthorizeCodeHandler>() with singleton {
            OAuthAuthorizeCodeHandler(
                authorizeCodeStrategy = instance(),
                authorizeCodeRepository = instance(),
                accessTokenHelper = AccessTokenHelper(
                    oauthContext = instance(),
                    accessTokenRepository = NoOpAccessTokenRepository,
                    accessTokenStrategy = instance()
                ),
                refreshTokenHelper = RefreshTokenHelper(
                    refreshTokenRepository = instance(),
                    refreshTokenStrategy = instance()
                )
            )
        }

        bind<OidcHybridHandler>() with singleton {
            OidcHybridHandler(
                oidcAuthorizeCodeHandler = OidcAuthorizeCodeHandler(
                    idTokenStrategy = instance(),
                    oidcSessionRepository = instance()
                ),
                idTokenStrategy = instance(),
                accessTokenHelper = AccessTokenHelper(
                    oauthContext = instance(),
                    accessTokenRepository = NoOpAccessTokenRepository,
                    accessTokenStrategy = instance()
                ),
                oidcSessionRepository = instance(),
                authorizeCodeRepository = instance(),
                authorizeCodeStrategy = instance()
            )
        }

        bind<HybridFlowService>() with singleton {
            HybridFlowService(
                authorizeHandlers = listOf(
                    instance<OidcHybridHandler>()
                ),
                exchangeHandlers = listOf(
                    instance<OAuthAuthorizeCodeHandler>(),
                    instance<OidcHybridHandler>()
                ),
                authorizeValidation = OAuthRequestValidationChain(listOf(
                    StateValidator(instance()),
                    NonceValidator(instance()),
                    ScopeValidator,
                    GrantedScopeValidator,
                    RedirectUriValidator,
                    OidcResponseTypeValidator
                )),
                exchangeValidation = OAuthRequestValidationChain(listOf(
                    OAuthGrantTypeValidator
                )),
                redisAuthorizeCodeRepository = instance()
            )
        }

        bind<HealthCheckHandler>() with singleton {
            HealthCheckHandler.create(vertx).apply {
                val redisClient = instance<RedisClient>()
                register("authorize_code_redis", 2000) { h ->
                    redisClient.ping { ar ->
                        if (ar.succeeded())
                            h.complete(Status.OK())
                        else
                            h.complete(Status.KO())
                    }
                }
            }
        }

        bind<GrpcVerticle>() with singleton {
            GrpcVerticle(
                flowService = instance(),
                appConfig = config,
                healthCheckHandler = instance()
            )
        }

        bind<HealthVerticle>() with singleton {
            HealthVerticle(healthCheckHandler = instance(), appConfig = config)
        }
    }
}

/**
 * Configuration context.
 */
class ServiceContext(config: Config, discovery: Discovery) : OidcContext, Discovery by discovery {
    override val idTokenLifespan: Duration = config.getDuration("service.idTokenLifespan")
    override val masterJsonWebKeySet: JsonWebKeySet = JsonWebKeySet(config.getString("service.jwks"))
    override val nonceEntropy: Int = config.getInt("service.nonceEntropy")
    override val issuerUrl: String = issuer
    override val authorizeEndpointUrl: String = authorizationEndpoint
    override val tokenEndpointUrl: String = tokenEndpoint
    override val defaultTokenEndpointAuthenticationMethod: String = AuthenticationMethod.clientSecretBasic
    override val authorizeCodeLifespan: Duration = config.getDuration("service.authorizeCodeLifespan")
    override val accessTokenLifespan: Duration = config.getDuration("service.accessTokenLifespan")
    override val refreshTokenLifespan: Duration = config.getDuration("service.refreshTokenLifespan")
    override val stateEntropy: Int = config.getInt("service.stateEntropy")
    val authorizeCodeKey = AesKey(Base64.getDecoder().decode(config.getString("service.authorizeCodeKey")))
    val refreshTokenKey = AesKey(Base64.getDecoder().decode(config.getString("service.refreshTokenKey")))
    override fun validate() { super<OidcContext>.validate() }
}
