package io.imulab.astrea.service.flow.hybrid.service

import io.grpc.stub.StreamObserver
import io.imulab.astrea.sdk.commons.flow.hybrid.*
import io.imulab.astrea.sdk.commons.toFailure
import io.imulab.astrea.sdk.flow.hybrid.toHybridCodeResponse
import io.imulab.astrea.sdk.flow.hybrid.toHybridTokenResponse
import io.imulab.astrea.sdk.flow.hybrid.toOAuthAccessRequest
import io.imulab.astrea.sdk.flow.hybrid.toOidcAuthorizeRequest
import io.imulab.astrea.sdk.oauth.error.OAuthException
import io.imulab.astrea.sdk.oauth.error.ServerError
import io.imulab.astrea.sdk.oauth.handler.AccessRequestHandler
import io.imulab.astrea.sdk.oauth.handler.AuthorizeRequestHandler
import io.imulab.astrea.sdk.oauth.validation.OAuthRequestValidationChain
import io.imulab.astrea.sdk.oidc.response.OidcAuthorizeEndpointResponse
import io.imulab.astrea.sdk.oidc.response.OidcTokenEndpointResponse
import io.imulab.astrea.service.flow.hybrid.persistence.RedisAuthorizeCodeRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import java.util.concurrent.Executors
import kotlin.coroutines.CoroutineContext

class HybridFlowService(
    private val concurrency: Int = 4,
    private val authorizeHandlers: List<AuthorizeRequestHandler>,
    private val exchangeHandlers: List<AccessRequestHandler>,
    private val redisAuthorizeCodeRepository: RedisAuthorizeCodeRepository,
    private val authorizeValidation: OAuthRequestValidationChain,
    private val exchangeValidation: OAuthRequestValidationChain
) : HybridFlowServiceGrpc.HybridFlowServiceImplBase(), CoroutineScope {

    override val coroutineContext: CoroutineContext
        get() = Executors.newFixedThreadPool(concurrency).asCoroutineDispatcher()

    override fun authorize(request: HybridCodeRequest?, responseObserver: StreamObserver<HybridCodeResponse>?) {
        if (request == null || responseObserver == null)
            return

        val job = Job()
        val authorizeRequest = request.toOidcAuthorizeRequest()
        val authorizeResponse = OidcAuthorizeEndpointResponse()

        launch(job) {
            authorizeValidation.validate(authorizeRequest)
            authorizeHandlers.forEach { h ->
                h.handleAuthorizeRequest(authorizeRequest, authorizeResponse)
            }

            if (!authorizeResponse.handledResponseTypes.containsAll(authorizeRequest.responseTypes))
                throw ServerError.internal("Some response types were not handled.")
        }.invokeOnCompletion { t ->
            if (t != null) {
                job.cancel()
                val e: OAuthException = if (t is OAuthException) t else ServerError.wrapped(t)
                responseObserver.onNext(
                    HybridCodeResponse.newBuilder()
                        .setSuccess(false)
                        .setFailure(e.toFailure())
                        .build()
                )
            } else {
                responseObserver.onNext(authorizeResponse.toHybridCodeResponse())
            }

            responseObserver.onCompleted()
        }
    }

    override fun exchange(request: HybridTokenRequest?, responseObserver: StreamObserver<HybridTokenResponse>?) {
        if (request == null || responseObserver == null)
            return

        val job = Job()
        val tokenRequest = request.toOAuthAccessRequest()
        val tokenResponse = OidcTokenEndpointResponse()

        launch(job) {
            exchangeValidation.validate(tokenRequest)

            exchangeHandlers.forEach { h -> h.updateSession(tokenRequest) }
            exchangeHandlers.forEach { h -> h.handleAccessRequest(tokenRequest, tokenResponse) }

            // safety mechanism in case the incoming request is OAuth only.
            // since the repository impl waits for the oidc handler to delete session, we may neglect
            // session deletion if the request is not OIDC scoped.
            // hence, as a safety, we force delete again here.
            redisAuthorizeCodeRepository.deleteOidcSession(tokenRequest.code)
        }.invokeOnCompletion { t ->
            if (t != null) {
                job.cancel()
                val e: OAuthException = if (t is OAuthException) t else ServerError.wrapped(t)
                responseObserver.onNext(
                    HybridTokenResponse.newBuilder()
                        .setSuccess(false)
                        .setFailure(e.toFailure())
                        .build()
                )
            } else {
                responseObserver.onNext(tokenResponse.toHybridTokenResponse())
            }
            responseObserver.onCompleted()
        }
    }
}