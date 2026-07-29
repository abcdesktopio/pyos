#!/usr/bin/env python3
#
# Software Name : abcdesktop.io
# Version: 0.2
# SPDX-FileCopyrightText: Copyright (c) 2020-2022 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
# This software is distributed under the GNU General Public License v2.0 only
# see the "license.txt" file for more details.
#
# Author: abcdesktop.io team
# Software description: cloud native desktop service
#

from __future__ import annotations

import json
import logging
import os
import signal
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask
# from fastapi_mcp import FastApiMCP

from collections.abc import AsyncIterable
from fastapi.sse import EventSourceResponse, ServerSentEvent
from pydantic import BaseModel

import oc.logging
import oc.od.settings as settings
import oc.od.services as services
from oc.cherrypy import Results
from oc.logging import set_request_context, reset_request_context
from oc.auth.authservice import set_auth_cache, reset_auth_cache

# import all controllers 
import controllers.accounting_controller
import controllers.auth_controller
import controllers.composer_controller
import controllers.core_controller  
import controllers.manager_controller
import controllers.store_controller
import controllers.user_controller

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan – remplace ODCherryWatcher (start/stop)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gère le démarrage et l'arrêt des services."""
    logger.info("Starting abcdesktop services...")
    
    # lifespan services initialization (kubernetes, snapregistry, etc)
    await services.lifespan()
    # start services 
    services.services.start()
    
    yield
    logger.info("Stopping abcdesktop services...")
    if isinstance(services.services, services.ODServices):
        services.services.stop()


# ---------------------------------------------------------------------------
# Application FastAPI
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:

    # Création de l'application FastAPI avec le gestionnaire de durée de vie
    app = FastAPI(
        title="abcdesktop API",
        version="0.2",
        lifespan=lifespan,
    )

    # CORS
    allow_origins = settings.config.get("default_host_url_accesscontrol_allow_origin", ["*"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Middleware : contexte de requête + cache auth
    # ------------------------------------------------------------------
    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        # Stocker la requête courante dans le ContextVar
        req_token = set_request_context(request)
        # Parser et stocker le cache d'auth pour cette requête
        auth_cache = services.services.auth.parse_auth_request(request)
        # Stocker aussi dans request.state pour le filtre de log
        request.state.odauthcache = auth_cache
        auth_token = set_auth_cache(auth_cache)
        try:
            response = await call_next(request)
        finally:
            reset_request_context(req_token)
            reset_auth_cache(auth_token)
        return response

    # ------------------------------------------------------------------
    # Middleware : logging des requêtes / réponses
    # ------------------------------------------------------------------
    # @app.middleware("http")
    async def trace_middleware(request: Request, call_next):
        # Log de la requête
        MAX_LOG_BODY = settings.max_log_body_size
        body_bytes = b""
        if request.method in ("POST", "PUT", "PATCH"):
            body_bytes = await request.body()
        if body_bytes:
            try:
                json_data = json.loads(body_bytes)
                # Masquer les données sensibles
                if isinstance(json_data, dict):
                    if json_data.get("result", {}).get("authorization"):
                        json_data = json_data.copy()
                        json_data["result"]["authorization"] = "XXXXXXXXXXX"
                    if json_data.get("password"):
                        json_data = json_data.copy()
                        json_data["password"] = "XXXXXXXXXXX"
                logmessage = f"{request.url.path} {json_data}"
            except Exception:
                logmessage = request.url.path
        else:
            logmessage = request.url.path
        logger.info(logmessage)

        response = await call_next(request)

        # Log de la réponse en tâche de fond (après envoi au client)
        if not getattr(request.state, "notrace", False):
            try:
                resp_body = b""
                async for chunk in response.body_iterator:
                    resp_body += chunk

                def log_response(path: str, body: bytes) -> None:
                    body_log = body[:MAX_LOG_BODY]
                    if len(body) > MAX_LOG_BODY:
                        body_log += b"...[truncated]"
                    logger.info(f"{path} {body_log.rstrip()}")

                return Response(
                    content=resp_body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type,
                    background=BackgroundTask(log_response, request.url.path, resp_body),
                )
            except Exception:
                pass
        return response

    # ------------------------------------------------------------------
    # Gestionnaire d'erreurs global
    # ------------------------------------------------------------------
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        result = {"status": exc.status_code, "message": exc.detail or "Internal server error"}
        return JSONResponse(status_code=exc.status_code, content=result)

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        status = getattr(exc, "code", None) or getattr(exc, "status", 500)
        message = None
        for attr in ["reason", "message", "_message", "description"]:
            if hasattr(exc, attr):
                message = getattr(exc, attr)
                if isinstance(message, (list, tuple)):
                    message = message[0]
                if isinstance(message, str) and message:
                    break
        if not isinstance(message, str):
            message = "Internal server error"
        result = {"status": status, "message": message}
        return JSONResponse(status_code=int(status), content=result)

    # ------------------------------------------------------------------
    # Routes de base
    # ------------------------------------------------------------------
    @app.api_route("/API/healthz", methods=["GET", "POST"])
    async def healthz(request: Request):
        request.state.notrace = True
        return Response(content="OK", media_type="text/plain")

    # ------------------------------------------------------------------
    # Montage des contrôleurs
    # ------------------------------------------------------------------
    _mount_controllers(app)

    # ------------------------------------------------------------------
    # Fichiers statiques (images)
    # ------------------------------------------------------------------
    try:
        app.mount("/img", StaticFiles(directory="img"), name="img")
    except Exception as e:
        logger.warning(f"Static files /img not mounted: {e}")

    return app


def _mount_controllers(app: FastAPI) -> None:
    """Importe et monte tous les contrôleurs (qui sont eux-mêmes des APIRouter)."""

    controllers_classes = [
        controllers.accounting_controller.AccountingController,
        controllers.auth_controller.AuthController,
        controllers.composer_controller.ComposerController,
        controllers.core_controller.CoreController,
        controllers.manager_controller.ManagerController,
        controllers.store_controller.StoreController,
        controllers.user_controller.UserController
    ]

    # instance et montage de chaque controller
    for controller in controllers_classes:
        mycontoller = controller( settings.controllers.get(controller.__name__))
        # keep a reference to the mounted controller instance so its
        # security configuration (apikey, permitip, enable, ...) can be
        # refreshed at runtime by settings.reload_config()
        services.services.controllers.append(mycontoller)
        app.include_router(mycontoller, prefix="/API")  

# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------

_server: uvicorn.Server | None = None


def _handle_signal(signame: str, *args) -> None:
    logger.warning(f"*** Received signal {signame}, shutting down...")
    if _server:
        _server.should_exit = True


# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------

def run_server() -> None:
    global _server
    logger.info("Starting FastAPI/uvicorn service...")

    app = create_app()

    host = os.environ.get("SERVER_HOST", "0.0.0.0")
    port = int(os.environ.get("SERVER_PORT", 8000))

    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        log_config=None,
        access_log=False,
        server_header=False,
        timeout_keep_alive=180
    )
    _server = uvicorn.Server(config)

    # Signal handlers
    for sig in (signal.SIGTERM, signal.SIGQUIT, signal.SIGINT):
        signal.signal(sig, lambda s, f, _sig=sig: _handle_signal(signal.Signals(_sig).name))

    logger.info(f"Listening on {host}:{port}")
    _server.run()


def main(argv) -> None:
    # Logging
    oc.logging.configure(config_or_path=settings.get_configuration_file_name(), is_cp_file=True)
    # Paramètres
    settings.init()
    # Services
    services.init()
    # Démarrage
    run_server()


if __name__ == "__main__":
    main(sys.argv[1:])
