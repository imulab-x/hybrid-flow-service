package io.imulab.astrea.service.flow.hybrid.service

import com.typesafe.config.Config
import io.vertx.core.AbstractVerticle
import io.vertx.core.http.HttpServerOptions
import io.vertx.ext.healthchecks.HealthCheckHandler
import io.vertx.ext.web.Router

class HealthVerticle(
    private val healthCheckHandler: HealthCheckHandler,
    private val appConfig: Config
) : AbstractVerticle() {
    override fun start() {
        val router = Router.router(vertx)
        router.get("/health").handler(healthCheckHandler)
        vertx.createHttpServer(HttpServerOptions().apply {
            port = appConfig.getInt("service.healthPort")
        }).requestHandler(router).listen()
    }
}