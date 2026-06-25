#!/usr/bin/env python3
#
# Software Name : abcdesktop.io
# Version: 0.2
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
# This software is distributed under the GNU General Public License v2.0 only
# see the "license.txt" file for more details.
#
# Author: abcdesktop.io team
# Software description: cloud native desktop service
#
import base64
import json
import logging
import urllib.parse

import chevron
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from fastapi import Request, Response
from fastapi.exceptions import HTTPException
from fastapi.responses import HTMLResponse

import oc.auth.authservice
import oc.lib
import oc.logging
import oc.od.composer
import oc.od.settings
import oc.od.tracking
from oc.cherrypy import Results, getclientipaddr, getclienthttp_header, getclientremote_ip
from oc.od.base_controller import BaseController
from oc.od.services import services

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class AuthController(BaseController):
    """Description: Authentification Controller"""

    redirect_page_local_filename = "redirect.mustache.html"

    def __init__(self, config_controller=None):
        self.logger.debug(f"config_controller={config_controller}")
        super().__init__(config_controller)
        try:
            self.oauth_html_redirect_page = oc.lib.load_local_file(
                filename=AuthController.redirect_page_local_filename
            )
        except Exception as e:
            self.logger.error(f"FATAL ERROR {AuthController.redirect_page_local_filename} file is missing")
            self.logger.error(f"http auth request will failed {e}")
            raise RuntimeError(f"missing file {AuthController.redirect_page_local_filename}")
        self.add_api_route("/getauthconfig",  self.getauthconfig,  methods=["POST"])
        self.add_api_route("/disconnect",     self.disconnect,     methods=["POST"])
        self.add_api_route("/logout",         self.logout,         methods=["POST"])
        self.add_api_route("/oauth",          self.oauth,          methods=["GET"])
        self.add_api_route("/auth",           self.auth,           methods=["POST"])
        self.add_api_route("/labels",         self.labels,         methods=["POST"])
        self.add_api_route("/buildsecret",    self.buildsecret,    methods=["POST"])
        self.add_api_route("/prelogin",       self.prelogin,       methods=["POST", "GET"])
        self.add_api_route("/autologin",      self.autologin,      methods=["POST"])
        self.add_api_route("/authorizedkeys", self.authorizedkeys, methods=["GET"])
        self.add_api_route("/logmein",        self.logmein,        methods=["POST", "GET"])
        self.add_api_route("/refreshtoken",   self.refreshtoken,   methods=["POST"])
        self.add_api_route("/login",          self.login,          methods=["POST"])

    # ------------------------------------------------------------------
    async def getauthconfig(self, request: Request) -> dict:
        """Get the authentification configuration."""
        return services.auth.getclientdata()

    async def disconnect(self, request: Request) -> dict:
        """Disconnect a connected user, keep desktop running."""
        self.logger.debug("disconnect")
        url = "/"
        if services.auth.isidentified:
            services.auth.logout(provider=services.auth.auth.provider, authinfo=services.auth.auth)
            return Results.success(result={"url": url})
        else:
            self.logger.error("user try to logout, but user is not identified")
            return Results.error(message="invalid user credentials", result={"url": url})

    async def logout(self, request: Request, redirect_uri: str = None) -> dict:
        """Logout a connected user, remove the desktop."""
        url = "/"
        if services.auth.isidentified:
            removedesktop = await oc.od.composer.removedesktop(services.auth.auth, services.auth.user)
            if removedesktop is True:
                response = Results.success(result={"url": url})
            else:
                response = Results.error(message="removedesktop failed")
                response["result"] = {"url": url}
            services.auth.logout(provider=services.auth.auth.provider, authinfo=services.auth.auth)
        else:
            response = Results.error(message="invalid user credentials")
            response["result"] = {"url": url}
        return response

    def build_redirecthtmlpage(self, jwt_user_token: str) -> str:
        # do not use HTTP redirect (Safari cookie bug with 302)
        mustache_dict = {
            "loginScreencss_url": "../../css/css-dist/loginScreen.css",
            "jwt_user_token": str(jwt_user_token),
            "default_host_url": "/",
        }
        return chevron.render(self.oauth_html_redirect_page, mustache_dict)

    async def oauth(self, request: Request) -> Response:
        self.required_controller_security_check(request)
        params = dict(request.query_params)
        params["manager"] = "external"  # OAuth MUST force 'external' manager
        self.update_features_args(args=params)
        self.check_features_permissions(args=params)
        response = services.auth.login(**params)
        self.checkloginresponseresult(response)
        await oc.od.composer.prepareressources(authinfo=response.result.auth, userinfo=response.result.user)
        jwt_user_token = services.auth.update_token(
            auth=response.result.auth, user=response.result.user, roles=response.result.roles
        )
        oc.od.tracking.addnewentryinloginhistory(auth=response.result.auth, user=response.result.user)
        oauth_html_refresh_page = self.build_redirecthtmlpage(jwt_user_token)
        return Response(
            content=oauth_html_refresh_page.encode("utf-8"),
            media_type="text/html;charset=utf-8",
            headers={"Refresh": "5; url=" + oc.od.settings.default_host_url},
        )

    async def auth(self, request: Request) -> dict:
        self.logger.debug("auth call start")
        try:
            args = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
        if not isinstance(args, dict):
            raise HTTPException(status_code=400, detail="invalid parameters")
        ipsource = getclientipaddr(request)
        self.required_controller_security_check(request, ipsource)
        self.check_features_permissions(args=args)

        http_attribut_to_force_auth_prelogin = request.headers.get(
            services.prelogin.http_attribut_to_force_auth_prelogin
        )
        if services.prelogin.enable and (
            services.prelogin.request_match(ipsource) or http_attribut_to_force_auth_prelogin
        ):
            userid = args.get("userid")
            if not isinstance(userid, str):
                raise HTTPException(status_code=401, detail="invalid auth parameters, request must use set userid")
            loginsessionid = args.get("loginsessionid")
            if not isinstance(loginsessionid, str):
                raise HTTPException(
                    status_code=401, detail="invalid auth parameters, request must use a prelogin session"
                )
            prelogin_verify = services.prelogin.prelogin_verify(sessionid=loginsessionid, userid=userid)
            if not prelogin_verify:
                self.fail_ip(request, ipsource)
                raise HTTPException(
                    status_code=401, detail="invalid auth request, verify prelogin request failed"
                )

        provider = args.get("provider")
        if provider is None and services.auth.is_default_metalogin_provider():
            response = services.auth.metalogin(**args)
        elif isinstance(provider, str) and len(provider) > 0:
            response = services.auth.login(**args)
        else:
            raise HTTPException(status_code=401, detail="missing provider parameter")

        self.checkloginresponseresult(response)
        services.accounting.accountex("login", "success")
        services.accounting.accountex("login", response.result.auth.providertype)

        try:
            await oc.od.composer.prepareressources(authinfo=response.result.auth, userinfo=response.result.user)
        except Exception as e:
            return Results.error(status=401, message=f"failed to prepare ressources {e}")

        expire_in = oc.od.settings.jwt_config_user.get("exp")
        jwt_user_token = services.auth.update_token(
            auth=response.result.auth, user=response.result.user, roles=response.result.roles
        )
        oc.od.tracking.addnewentryinloginhistory(auth=response.result.auth, user=response.result.user)
        return Results.success(
            message=response.reason,
            result={
                "userid": response.result.user.userid,
                "jwt_user_token": jwt_user_token,
                "name": response.result.user.name,
                "provider": response.result.auth.providertype,
                "expire_in": expire_in,
            },
        )

    async def labels(self, request: Request) -> dict:
        if services.auth.isidentified:
            auth = services.auth.auth
            return Results.success(result=auth.get_labels())
        return Results.error(message="invalid user credentials")

    async def buildsecret(self, request: Request) -> dict:
        self.logger.debug("")
        try:
            args = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
        if not isinstance(args, dict):
            raise HTTPException(status_code=400, detail="invalid parameters")
        password = args.get("password")
        if not isinstance(password, str):
            raise HTTPException(status_code=400, detail="Bad request invalid password parameter")

        (auth, user, roles) = self.validate_env(request)
        args_login = {"userid": user.userid, "password": password}
        response = services.auth.su(source_provider_name=auth.provider, arguments=args_login)
        self.checkloginresponseresult(response, msg="su")
        await oc.od.composer.prepareressources(authinfo=response.result.auth, userinfo=response.result.user)
        jwt_user_token = services.auth.update_token(
            auth=response.result.auth, user=response.result.user, roles=response.result.roles
        )
        return Results.success(
            message="Authentication successful",
            result={
                "userid": response.result.user.userid,
                "name": response.result.user.name,
                "jwt_user_token": jwt_user_token,
                "provider": response.result.auth.providertype,
                "expire_in": oc.od.settings.jwt_config_user.get("exp"),
            },
        )

    async def prelogin(self, request: Request, userid: str = None) -> Response:
        ipsource = getclientipaddr(request)
        self.logger.debug(f"prelogin request from ip source {ipsource}")
        self.required_controller_security_check(request, ipsource)

        if not services.prelogin.enable:
            self.logger.error("prelogin service is disabled in configuration file")
            raise HTTPException(status_code=400, detail="prelogin service is disabled in configuration file")

        http_attribut_to_force_auth_prelogin = request.headers.get(
            services.prelogin.http_attribut_to_force_auth_prelogin
        )
        is_http_attribut_exist = isinstance(http_attribut_to_force_auth_prelogin, str)
        is_ipsource_match = services.prelogin.request_match(ipsource)
        if not is_http_attribut_exist and not is_ipsource_match:
            self.fail_ip(request, ipsource)
            raise HTTPException(status_code=400, detail="prelogin service is denied, invalid request parameters")

        if isinstance(services.prelogin.http_attribut, str):
            http_userid = request.headers.get(services.prelogin.http_attribut)
            if isinstance(http_userid, str):
                userid = http_userid

        if not isinstance(userid, str) or len(userid) == 0:
            raise HTTPException(status_code=400, detail="invalid userid request parameter")

        userid = urllib.parse.unquote(userid)
        html_data = services.prelogin.prelogin_html(userid=userid)
        if not isinstance(html_data, str) or len(html_data) == 0:
            raise HTTPException(status_code=400, detail="Configuration file error, prelogin url fetch failed")

        return Response(
            content=html_data.encode("utf-8"),
            media_type="text/html; charset=utf-8",
            headers={"Cache-Control": "no-cache, private"},
        )

    async def autologin(
        self, request: Request, login: str = None, provider: str = None, password: str = None
    ) -> Response:
        self.logger.debug("")
        self.required_controller_security_check(request)

        if oc.od.settings.services_http_request_denied.get("autologin", True) is True:
            raise HTTPException(status_code=400, detail="request is denied by configfile")
        if not isinstance(login, str):
            raise HTTPException(status_code=400, detail="Bad request invalid login parameter")
        if password is not None and not isinstance(password, str):
            raise HTTPException(status_code=400, detail="Bad request invalid password parameter")

        args_login = {
            "manager": "explicit",
            "password": password,
            "provider": provider,
            "userid": login,
            "auto": True,
        }
        response = services.auth.login(**args_login)
        self.checkloginresponseresult(response)
        await oc.od.composer.prepareressources(authinfo=response.result.auth, userinfo=response.result.user)
        jwt_user_token = services.auth.update_token(
            auth=response.result.auth, user=response.result.user, roles=response.result.roles
        )
        oauth_html_refresh_page = self.build_redirecthtmlpage(jwt_user_token)
        return Response(
            content=oauth_html_refresh_page.encode("utf-8"),
            media_type="text/html;charset=utf-8",
            headers={"Refresh": "5; url=" + oc.od.settings.default_host_url},
        )

    def handler_logmein_json(self, jwt_user_token: str) -> Response:
        jwt_user = {"jwt_user_token": jwt_user_token}
        result_jwt = Results.success("login success", result=jwt_user)
        return Response(
            content=(json.dumps(result_jwt) + "\n").encode("utf-8"),
            media_type="application/json;charset=utf-8",
        )

    def handler_logmein_html(self, jwt_user_token: str) -> Response:
        oauth_html_refresh_page = self.build_redirecthtmlpage(jwt_user_token)
        return Response(
            content=oauth_html_refresh_page.encode("utf-8"),
            media_type="text/html;charset=utf-8",
            headers={
                "Cache-Control": "no-cache, private",
                "Refresh": "5; url=" + oc.od.settings.default_host_url,
            },
        )

    def handler_logmein_text(self, jwt_desktop: str) -> Response:
        return Response(
            content=(jwt_desktop + "\n").encode("utf-8"),
            media_type="text/text;charset=utf-8",
            headers={"Cache-Control": "no-cache, private"},
        )

    def handler_authorizedkeys_json(self, data) -> Response:
        return Response(
            content=(json.dumps(data) + "\n").encode("utf-8"),
            media_type="application/json;charset=utf-8",
        )

    def handler_authorizedkeys_text(self, data) -> Response:
        return Response(
            content=f"{data}\n".encode("ascii"),
            media_type="text/text;charset=ascii",
            headers={"Cache-Control": "no-cache, private"},
        )

    async def authorizedkeys(self, request: Request) -> Response:
        ipsource = getclientipaddr(request)
        self.required_controller_security_check(request, ipsource)
        routecontenttype = {
            "application/json": self.handler_authorizedkeys_json,
            "text/plain": self.handler_authorizedkeys_text,
        }
        data = services.authorized_keys.list()
        if isinstance(data, list):
            return self.getlambdaroute(routecontenttype, defaultcontenttype="text/plain", request=request)(data)
        return data

    async def logmein(
        self, request: Request, provider: str = None, userid: str = None, format: str = "deprecated"
    ) -> Response:
        ipsource = getclientipaddr(request)
        self.required_controller_security_check(request, ipsource)

        if not services.logmein.enable:
            raise HTTPException(status_code=400, detail="logmein configuration file error, service is disabled")

        remote_ip = getclientremote_ip(request)
        if not services.logmein.request_match(remote_ip):
            raise HTTPException(status_code=400, detail="logmein invalid network source error")

        if services.logmein.permit_querystring:
            if isinstance(userid, str) and len(userid) > 0:
                userid = urllib.parse.unquote(userid)

        cert_info = None
        if isinstance(services.logmein.http_attribut, str):
            cert = request.headers.get(services.logmein.http_attribut)
            if isinstance(cert, str):
                strcert = urllib.parse.unquote(cert)
                if not strcert.startswith("-----BEGIN"):
                    strcert = "-----BEGIN CERTIFICATE-----\n" + strcert + "\n-----END CERTIFICATE-----"
                cert_info = x509.load_pem_x509_certificate(strcert.encode(), default_backend())
                if not isinstance(cert_info, x509.Certificate):
                    raise HTTPException(status_code=400, detail="Bad certificate")
                for oid in services.logmein.oid_query_list:
                    try:
                        cert_info_data = cert_info.subject.get_attributes_for_oid(oid)[0].value
                        if isinstance(cert_info_data, str) and len(cert_info_data) > 0:
                            userid = cert_info_data
                            break
                    except Exception as e:
                        self.logger.error(f"skipping certificat subject read {oid} error {e}")

        if not isinstance(userid, str) or len(userid) == 0:
            raise HTTPException(status_code=400, detail="logmein invalid user parameter")

        if cert_info is not None:
            if not services.authorized_keys.add_key(userid, cert_info):
                self.logger.error(
                    f"Failed to add public key to authorized keys, userid={userid}, cert subject={cert_info.subject}"
                )

        response = services.auth.login(provider=provider, manager="implicit", userid=userid)
        self.checkloginresponseresult(response)
        await oc.od.composer.prepareressources(authinfo=response.result.auth, userinfo=response.result.user)
        jwt_user_token = services.auth.update_token(
            auth=response.result.auth, user=response.result.user, roles=response.result.roles
        )
        routecontenttype = {
            "text/html": self.handler_logmein_html,
            "application/json": self.handler_logmein_json,
            "text/plain": self.handler_logmein_text,
        }
        return self.getlambdaroute(routecontenttype, defaultcontenttype="text/html", request=request)(jwt_user_token)

    async def refreshtoken(self, request: Request) -> Response:
        self.logger.debug("")
        (auth, user, roles) = self.validate_env(request)
        jwt_user_token = services.auth.update_token(auth=auth, user=user, roles=roles)
        result = Results.success(
            "Refresh token success",
            result={"jwt_user_token": jwt_user_token, "expire_in": oc.od.settings.jwt_config_user.get("exp")},
        )
        return Response(
            content=json.dumps(result).encode("utf-8"),
            media_type="application/json;charset=utf-8",
            headers={
                "Cache-Control": "no-cache, private",
                "X-Content-Type-Options": "nosniff",
            },
        )

    async def login(self, request: Request):
        (auth, user, roles) = self.validate_env(request)
        try:
            args = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
        if not isinstance(args, dict):
            raise HTTPException(status_code=400, detail="invalid parameters")

        async for item in self.root.composer._launchdesktop(auth, user, roles, args, request):
            yield item

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def checkloginresponseresult(self, response: oc.auth.authservice.AuthResponse, msg: str = "login") -> None:
        if not isinstance(response, oc.auth.authservice.AuthResponse):
            error = f"services auth.{msg} does not return AuthResponse object"
            self.logger.error(error)
            raise HTTPException(status_code=401, detail=error)
        if not response.success:
            message = None
            for m in ["reason", "message", "_message"]:
                if hasattr(response, m):
                    message = getattr(response, m)
                    break
            self.logger.error(f"services auth.{msg} error {message}")
            raise HTTPException(status_code=401, detail=message)

    def check_features_permissions(self, args: dict) -> None:
        if args.get("features") is not None:
            if isinstance(args.get("features"), dict):
                if "submit" not in oc.od.settings.desktop["features_permissions"]:
                    raise HTTPException(
                        status_code=401,
                        detail="'submit' is not in desktop.features_permissions, update configuration file",
                    )
            else:
                raise HTTPException(status_code=401, detail="bad parameters features, features must be a dict")

    def update_features_args(self, args: dict) -> None:
        if isinstance(args, dict):
            state = args.get("state")
            if isinstance(state, str):
                try:
                    decoded_state = base64.b64decode(state.encode("ascii")).decode()
                    dict_state = json.loads(decoded_state)
                    if isinstance(dict_state, dict):
                        args["features"] = dict_state
                except Exception as e:
                    self.logger.debug(e)
