#!/usr/bin/env python3
#
# Software Name : abcdesktop.io
# Version: 0.2
# SPDX-FileCopyrightText: Copyright (c) 2020-2021 Orange
# SPDX-License-Identifier: GPL-2.0-only
#
import datetime
import logging

from fastapi import Request, Response
from fastapi.exceptions import HTTPException

import oc.logging
import oc.od.composer
import oc.od.services
from oc.od.base_controller import BaseController
from oc.od.services import services

logger = logging.getLogger(__name__)


@oc.logging.with_logger()
class ManagerController(BaseController):
    """Description: Manager Controller"""

    def __init__(self, config_controller=None):
        super().__init__(config_controller)
        self.add_api_route("/healtz",                   self.healtz,                   methods=["GET"])
        self.add_api_route("/config",                   self.config,                   methods=["GET", "POST"])
        self.add_api_route("/echohttp",                 self.echohttp,                 methods=["GET", "POST"])
        self.add_api_route("/buildapplist",             self.buildapplist,             methods=["GET"])
        self.add_api_route("/updateactivedirectorysite",self.updateactivedirectorysite,methods=["GET"])
        self.add_api_route("/garbagecollector",         self.garbagecollector,         methods=["GET"])
        self.add_api_route("/datastore/{path:path}",    self.datastore,                methods=["GET", "PUT", "DELETE"])
        self.add_api_route("/desktop",                  self.desktop,                  methods=["GET"])
        self.add_api_route("/desktop/{path:path}",      self.desktop,                  methods=["GET", "DELETE"])
        self.add_api_route("/images",                   self.images,                   methods=["GET", "DELETE"])
        self.add_api_route("/image/{path:path}",        self.image,                    methods=["GET", "PUT", "POST", "DELETE", "PATCH"])
        self.add_api_route("/ban/{collection}/{path:path}", self.ban,                  methods=["GET", "POST", "DELETE"])
        self.add_api_route("/ban/{collection}",         self.ban_root,                 methods=["GET", "POST", "DELETE"])

    async def healtz(self, request: Request) -> dict:
        self.is_permit_request(request)
        request.state.notrace = True
        return {"controler": self.__class__.__name__, "status": "ok"}

    async def config(self, request: Request) -> dict:
        self.is_permit_request(request)
        if request.method == "GET":
            return self.handle_config_GET()
        elif request.method == "POST":
            try:
                body = await request.json()
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
            return await self.handle_config_POST(body)
        return oc.od.settings.config

    def handle_config_GET(self) -> dict:
        return oc.od.settings.config

    def handle_config_POST(self, json_config: dict) -> dict:
        if not isinstance(json_config, dict):
            raise HTTPException(status_code=400, detail="invalid parameters")
        oc.od.settings.config.update(json_config)
        return oc.od.settings.config
    
    async def echohttp(self, request: Request) -> dict:
        self.is_permit_request(request)
        http_dump = {
            "headers": dict(request.headers),
            "remote":  request.client._asdict() if request.client else {},
            "params":  dict(request.query_params),
        }
        self.logger.debug(http_dump)
        return http_dump

    async def buildapplist(self, request: Request) -> dict:
        self.is_permit_request(request)
        request.state.notrace = True
        oc.od.services.services.apps.cached_applist(bRefresh=True)
        return oc.od.services.services.apps.get_json_applist(filter=True)

    async def updateactivedirectorysite(self, request: Request) -> dict:
        self.is_permit_request(request)
        request.state.notrace = True
        return oc.od.services.services.update_locator()

    async def garbagecollector(
        self, request: Request, expirein: int = None, nodename: str = None, force: bool = False, snapshot: bool = False
    ) -> dict:
        self.logger.debug("")
        self.is_permit_request(request)
        request.state.notrace = True
        if expirein is None:
            raise HTTPException(status_code=400, detail="invalid parameters")
        try:
            nexpirein = int(expirein)
            if isinstance(force, str):
                force = oc.lib.strtobool(str(force))
            else:
                force = bool(force)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid parameters")
        return await oc.od.composer.garbagecollector(expirein=nexpirein, nodename=nodename, force=force, snapshot=snapshot)

    async def datastore(self, request: Request, path: str = "") -> dict:
        self.is_permit_request(request)
        args = tuple(path.split("/")) if path else ()
        if request.method == "GET":
            return  self.handle_datastore_GET(args)
        elif request.method == "PUT":
            try:
                body = await request.json()
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
            return self.handle_datastore_PUT(args, body)
        elif request.method == "DELETE":
            return self.handle_datastore_DELETE(args)
        raise HTTPException(status_code=405, detail="Method Not Allowed")

    async def desktop(self, request: Request, path: str = "") -> dict | list | bool:
        self.is_permit_request(request)
        args = tuple(path.split("/")) if path else ()
        if request.method == "GET":
            return await self.handle_desktop_GET(args)
        elif request.method == "DELETE":
            return await self.handle_desktop_DELETE(args)
        raise HTTPException(status_code=405, detail="Method Not Allowed")

    async def images(self, request: Request) -> dict:
        self.is_permit_request(request)
        if request.method == "GET":
            return self.handle_images_GET()
        elif request.method == "DELETE":
            return self.handle_images_DELETE()
        raise HTTPException(status_code=405, detail="Method Not Allowed")

    async def image(self, request: Request, image: str = None, node: str = None) -> dict|list:
        self.is_permit_request(request)
        if request.method == "GET":
            return self.handle_image_GET(image=image)
        elif request.method == "PUT":
            try:
                body = await request.json()
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
            return self.handle_image_PUT(json_images=body, node=node)
        elif request.method == "POST":
            try:
                body = await request.json()
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
            return self.handle_image_POST(json_images=body)
        elif request.method == "DELETE":
            return self.handle_image_DELETE(image=image)
        elif request.method == "PATCH":
            try:
                body = await request.json()
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"invalid parameters: {e}")
            return self.handle_image_PATCH(image=image, json_images=body)
        raise HTTPException(status_code=405, detail="Method Not Allowed")

    async def ban(self, request: Request, collection: str, path: str = "") -> dict:
        self.is_permit_request(request)
        args = tuple(path.split("/")) if path else ()
        if request.method == "GET":
            return self.handle_ban_GET(collection, args)
        elif request.method == "POST":
            return self.handle_ban_POST(collection, args)
        elif request.method == "DELETE":
            return self.handle_ban_DELETE(collection, args)
        raise HTTPException(status_code=405, detail="Method Not Allowed")

    async def ban_root(self, request: Request, collection: str) -> dict:
        return await self.ban(request, collection, "")

    # ------------------------------------------------------------------
    # Handle datastore
    # ------------------------------------------------------------------

    def handle_datastore_GET(self, args: tuple):
        self.logger.debug("")
        if "read" not in self.database_acl and "get" not in self.database_acl:
            raise HTTPException(status_code=400, detail="'get' is denied")
        if not isinstance(args, tuple):
            raise HTTPException(status_code=400, detail="invalid request")

        value = None
        if len(args) == 0:
            value = oc.od.settings.mongodblist
        elif len(args) == 1:
            value = services.datastore.list_collections(databasename=args[0])
        elif len(args) == 2:
            value = services.datastore.getcollection(databasename=args[0], collectionname=args[1])
        elif len(args) == 3:
            collection_filter = {"kind": args[2]}
            value = services.datastore.getcollection(databasename=args[0], collectionname=args[1], myfilter=collection_filter)
        elif len(args) == 4:
            if args[2] not in ["after", "before"]:
                raise HTTPException(status_code=400, detail="invalid request filter must be 'after' or 'before'")
            try:
                iso_date = datetime.datetime.strptime(args[3], "%Y-%m-%d %H:%M:%S")
            except Exception:
                raise HTTPException(status_code=400, detail='invalid date format, default date format is "%Y-%m-%d %H:%M:%S"')
            collection_filter = {"date": {"$gte": iso_date} if args[2] == "after" else {"$lt": iso_date}}
            value = services.datastore.getcollection(databasename=args[0], collectionname=args[1], myfilter=collection_filter)
        elif len(args) == 6:
            if args[2] != "after":
                raise HTTPException(status_code=400, detail="invalid request first filter must equal to 'after'")
            if args[4] != "before":
                raise HTTPException(status_code=400, detail="invalid request second filter must equal to 'before'")
            try:
                iso_date_after = datetime.datetime.strptime(args[3], "%Y-%m-%d %H:%M:%S")
            except Exception:
                raise HTTPException(status_code=400, detail='invalid after date format')
            try:
                iso_date_before = datetime.datetime.strptime(args[5], "%Y-%m-%d %H:%M:%S")
            except Exception:
                raise HTTPException(status_code=400, detail='invalid before date format')
            collection_filter = {"date": {"$gte": iso_date_after, "$lt": iso_date_before}}
            value = services.datastore.getcollection(databasename=args[0], collectionname=args[1], myfilter=collection_filter)
        else:
            raise HTTPException(status_code=400, detail="invalid request")

        services.datastore.stringify(value)
        return value

    def handle_datastore_PUT(self, args: tuple, json_object) -> bool:
        self.logger.debug("")
        if "write" not in self.database_acl and "put" not in self.database_acl:
            raise HTTPException(status_code=400, detail="put is denied")
        if not isinstance(args, tuple) or len(args) != 3:
            raise HTTPException(status_code=400, detail="invalid request")
        if  services.datastore.set_document_value_in_collection(args[0], args[1], args[2], json_object) is True:
            return True
        raise HTTPException(status_code=400, detail="set_document_value_in_collection failed")

    async def handle_datastore_DELETE(self, args: tuple):
        self.logger.debug("")
        if "delete" not in self.database_acl:
            raise HTTPException(status_code=400, detail="delete is denied")
        if not isinstance(args, tuple):
            raise HTTPException(status_code=400, detail="invalid request")
        if len(args) == 2:
            return services.datastore.drop_collection(databasename=args[0], collectionname=args[1])
        elif len(args) == 3:
            return services.datastore.delete_one_in_colection(databasename=args[0], collectionname=args[1], key=args[2])
        raise HTTPException(status_code=400, detail="invalid request")

    # ------------------------------------------------------------------
    # Handle desktop
    # ------------------------------------------------------------------

    async def handle_desktop_GET(self, args: tuple):
        self.logger.debug("")
        if not isinstance(args, tuple):
            raise HTTPException(status_code=400, detail="invalid request")
        if len(args) == 0:
            return await oc.od.composer.list_desktop()
        desktop_name = args[0]
        if not isinstance(desktop_name, str):
            raise HTTPException(status_code=400, detail="Invalid parameters")
        if len(args) == 1:
            return await oc.od.composer.describe_desktop_byname(desktop_name)
        if len(args) > 1:
            if args[1] == "resources_usage" and len(args) == 2:
                return await oc.od.composer.get_desktop_resources_usage(desktop_name)
            if args[1] == "pod":
                if len(args) == 2:
                    return await oc.od.composer.list_applications_by_name_and_type(desktop_name, "pod_application")
                if len(args) == 3:
                    return await oc.od.composer.describe_application_byname(desktop_name, args[2])
                if len(args) == 4 and args[3] == "resources_usage":
                    return await oc.od.composer.get_pod_resources_usage(desktop_name=desktop_name, pod_name=args[2])
            if args[1] == "container":
                if len(args) == 2:
                    return await oc.od.composer.list_applications_by_name_and_type(desktop_name, "ephemeral_container")
                if len(args) == 3:
                    return await oc.od.composer.describe_application_byname(desktop_name, app_name=args[2])
                if len(args) == 4 and args[3] == "resources_usage":
                    container_name = args[2]
                    if not isinstance(container_name, str):
                        raise HTTPException(status_code=400, detail="Invalid parameters")
                    return await oc.od.composer.get_container_resources_usage(desktop_name=desktop_name, container_name=container_name)
        raise HTTPException(status_code=400, detail="Invalid parameters")

    async def handle_desktop_DELETE(self, args: tuple):
        self.logger.debug("")
        if not isinstance(args, tuple) or len(args) == 0:
            raise HTTPException(status_code=400, detail="Invalid parameters")
        desktop_name = args[0]
        if not isinstance(desktop_name, str):
            raise HTTPException(status_code=400, detail="Invalid parameters")
        if len(args) == 1:
            return await oc.od.composer.remove_desktop_byname(desktop_name)
        if len(args) == 3 and args[1] in ["container", "pod"]:
            return await oc.od.composer.stop_container_byname(desktop_name, container=args[2])
        raise HTTPException(status_code=400, detail="Invalid parameters")

    # ------------------------------------------------------------------
    # Handle images
    # ------------------------------------------------------------------

    def handle_images_GET(self):
        return oc.od.services.services.apps.get_json_applist()

    def handle_images_DELETE(self):
        return oc.od.composer.del_application_all_images()

    def handle_image_GET(self, image: str = None):
        if image is None:
            return oc.od.services.services.apps.get_json_applist()
        elif isinstance(image, str):
            app = oc.od.services.services.apps.get_json_app(image_id=image)
            if isinstance(app, dict):
                return app
            raise HTTPException(status_code=404, detail="Not found")
        raise HTTPException(status_code=400, detail="Invalid parameters")

    def handle_image_PUT(self, json_images, node: str = None):
        if (isinstance(node, str) or node is None) and isinstance(json_images, (list, dict)):
            return oc.od.composer.add_application_image(json_images)
        raise HTTPException(status_code=400, detail="Invalid parameters")

    def handle_image_POST(self, json_images):
        if isinstance(json_images, (list, dict)):
            return oc.od.composer.add_application_image(json_images)
        raise HTTPException(status_code=400, detail="Invalid parameters")

    def handle_image_DELETE(self, image:str )->list:
        if not isinstance(image, str):
            raise HTTPException(status_code=400, detail="Invalid parameters")
        if image == "*":
            return oc.od.composer.del_application_all_images()
        del_images = oc.od.composer.del_application_image(image)
        if isinstance(del_images, list) and len(del_images) > 0:
            return del_images
        raise HTTPException(status_code=404, detail="Not found")

    def handle_image_PATCH(self, image: str = None, json_images=None):
        if image is None:
            oc.od.services.services.apps.cached_applist(bRefresh=True)
            return oc.od.services.services.apps.get_json_applist()
        if isinstance(json_images, list):
            json_images = json_images[0]
        if isinstance(image, str) and isinstance(json_images, dict):
            app = oc.od.services.services.apps.find_app_by_id(image_id=image)
            if isinstance(app, dict):
                app_add = oc.od.services.services.apps.add_json_image_to_collection(json_images)
                if isinstance(app_add, dict):
                    return oc.od.services.services.apps.get_json_app(app_add.get("id"))
                return None
            raise HTTPException(status_code=404, detail="Not found")
        raise HTTPException(status_code=400, detail="Invalid parameters")

    # ------------------------------------------------------------------
    # Handle ban
    # ------------------------------------------------------------------

    def handle_ban_GET(self, collection: str, args: tuple):
        if not isinstance(collection, str) or not services.fail2ban.iscollection(collection):
            raise HTTPException(status_code=400, detail="Invalid collection")
        if len(args) == 0:
            return services.fail2ban.listban(collection_name=collection)
        elif len(args) == 1:
            return services.fail2ban.find_ban(args[0], collection_name=collection)
        raise HTTPException(status_code=400, detail="Invalid parameters")

    def handle_ban_POST(self, collection: str, args: tuple):
        if not services.fail2ban.iscollection(collection) or len(args) != 1:
            raise HTTPException(status_code=400, detail="Invalid parameters")
        ban = services.fail2ban.ban(args[0], collection_name=collection)
        if ban is None:
            raise HTTPException(status_code=500, detail="ban failed")
        if isinstance(ban, str):
            raise HTTPException(status_code=400, detail=ban)
        return ban

    def handle_ban_DELETE(self, collection: str, args: tuple):
        if not services.fail2ban.iscollection(collection):
            raise HTTPException(status_code=400, detail="Invalid collection")
        if len(args) == 0:
            return services.fail2ban.drop(collection_name=collection)
        if len(args) == 1:
            return services.fail2ban.unban(args[0], collection_name=collection)
        raise HTTPException(status_code=400, detail="Invalid parameters")


import oc.lib  # noqa: E402
import oc.od.settings  # noqa: E402
