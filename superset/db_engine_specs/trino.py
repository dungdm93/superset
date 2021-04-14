# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from datetime import datetime
from typing import Any, Dict, Optional, TYPE_CHECKING
from urllib import parse

from requests.auth import AuthBase
from sqlalchemy.engine.url import URL
from trino.auth import Authentication

from superset.db_engine_specs.base import BaseEngineSpec
from superset.utils import core as utils

if TYPE_CHECKING:
    from superset.models.core import Database


class OHTTPAuth2Auth(AuthBase):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        token_endpoint: str,
        ca_bundle: Optional[str] = None,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_endpoint = token_endpoint
        self._ca_bundle = ca_bundle

        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None

    def __call__(self, *args, **kwargs):
        pass


class OAuth2ClientCredentialsAuthentication(Authentication):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        token_endpoint: str,
        ca_bundle: Optional[str] = None,
    ) -> None:
        self._auth = OHTTPAuth2Auth(
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint=token_endpoint,
            ca_bundle=ca_bundle,
        )

    def set_client_session(self, client_session):
        pass

    def set_http_session(self, http_session):
        http_session.auth = self._auth
        return http_session

    def setup(self, trino_client):
        self.set_client_session(trino_client.client_session)
        self.set_http_session(trino_client.http_session)

    def get_exceptions(self):
        return ()

    def handle_error(self, handle_error):
        pass


class TrinoEngineSpec(BaseEngineSpec):
    engine = "trino"
    engine_name = "Trino"

    # pylint: disable=line-too-long
    _time_grain_expressions = {
        None: "{col}",
        "PT1S": "date_trunc('second', CAST({col} AS TIMESTAMP))",
        "PT1M": "date_trunc('minute', CAST({col} AS TIMESTAMP))",
        "PT1H": "date_trunc('hour', CAST({col} AS TIMESTAMP))",
        "P1D": "date_trunc('day', CAST({col} AS TIMESTAMP))",
        "P1W": "date_trunc('week', CAST({col} AS TIMESTAMP))",
        "P1M": "date_trunc('month', CAST({col} AS TIMESTAMP))",
        "P0.25Y": "date_trunc('quarter', CAST({col} AS TIMESTAMP))",
        "P1Y": "date_trunc('year', CAST({col} AS TIMESTAMP))",
        # "1969-12-28T00:00:00Z/P1W",  # Week starting Sunday
        # "1969-12-29T00:00:00Z/P1W",  # Week starting Monday
        # "P1W/1970-01-03T00:00:00Z",  # Week ending Saturday
        # "P1W/1970-01-04T00:00:00Z",  # Week ending Sunday
    }

    @classmethod
    def convert_dttm(cls, target_type: str, dttm: datetime) -> Optional[str]:
        tt = target_type.upper()
        if tt == utils.TemporalType.DATE:
            value = dttm.date().isoformat()
            return f"from_iso8601_date('{value}')"
        if tt == utils.TemporalType.TIMESTAMP:
            value = dttm.isoformat(timespec="microseconds")
            return f"from_iso8601_timestamp('{value}')"
        return None

    @classmethod
    def epoch_to_dttm(cls) -> str:
        return "from_unixtime({col})"

    @classmethod
    def adjust_database_uri(
        cls, uri: URL, selected_schema: Optional[str] = None
    ) -> None:
        database = uri.database
        if selected_schema and database:
            selected_schema = parse.quote(selected_schema, safe="")
            database = database.split("/")[0] + "/" + selected_schema
            uri.database = database

    @staticmethod
    def get_extra_params(database: "Database") -> Dict[str, Any]:
        extra: Dict[str, Any] = BaseEngineSpec.get_extra_params(database)
        engine_params: Dict[str, Any] = extra.setdefault("engine_params", {})
        connect_args: Dict[str, Any] = engine_params.setdefault("connect_args", {})

        if database.server_cert:
            connect_args["http_scheme"] = "https"
            connect_args["verify"] = utils.create_ssl_cert_file(database.server_cert)

        return extra

    @staticmethod
    def get_encrypted_extra_params(database: "Database") -> Dict[str, Any]:
        extra: Dict[str, Any] = BaseEngineSpec.get_encrypted_extra_params(database)

        auth_method = extra.pop("auth_method", None)
        auth_params = extra.pop("auth_params", {})
        if not auth_method:
            return extra
        if auth_method == "kerberos":
            from trino.auth import KerberosAuthentication
            extra["auth"] = KerberosAuthentication(**auth_params)
        if auth_method == "oauth2_client_credentials":
            extra["auth"] = OAuth2ClientCredentialsAuthentication(**auth_params)
        return extra
