"""
    Copyright (c) 2023 Ingo Lafrenz <opnsense@der-ingo.de>
    Copyright (c) 2023 Ad Schellevis <ad@opnsense.org>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
    ----------------------------------------------------------------------------------------------------
    Netcup DNS provider, see https://ccp.netcup.net/run/webservice/servers/endpoint.php

"""
import json
import syslog
import requests
from . import BaseAccount
import base64
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.serialization

class TransIP(BaseAccount):
    _priority = 65535

    _services = {
        'transip': 'api.transip.nl'
    }

    def __init__(self, account: dict):
        super().__init__(account)

    @staticmethod
    def known_services():
        return {'transip': 'TransIP'}

    @staticmethod
    def match(account):
        return account.get('service') in TransIP._services

    def execute(self):
        if super().execute():
            # Determine record type based on the IP format
            record_type = "AAAA" if str(self.current_address).find(':') > -1 else "A"

            # Get API token
            try:
                token = self._request_token()
            except Exception as ex:
                syslog.syslog(syslog.LOG_ERR, f"Account {self.description} error obtaining token: {ex}")
                return False

            # Fetch DNS entries
            domain = self.settings.get('zone')
            endpoint = f"domains/{domain}/dns"
            try:
                dns_entries = self._request_get(endpoint, token)["dnsEntries"]
            except Exception as ex:
                syslog.syslog(syslog.LOG_ERR, f"Account {self.description} error fetching DNS entries: {ex}")
                return False

            # Update DNS records
            hostname = self.settings.get('hostnames')
            for entry in dns_entries:
                if entry["name"] == hostname and entry["type"] == record_type:
                    if entry["content"] != str(self.current_address):
                        entry["content"] = str(self.current_address)
                        try:
                            self._request_patch(endpoint, token, {"dnsEntry": entry})
                            syslog.syslog(
                                syslog.LOG_NOTICE,
                                f"Account {self.description} updated {hostname} to {self.current_address}"
                            )
                            self.update_state(address=self.current_address)
                            return True
                        except Exception as ex:
                            syslog.syslog(syslog.LOG_ERR, f"Account {self.description} error updating DNS entry: {ex}")
                            return False

            syslog.syslog(
                syslog.LOG_NOTICE,
                f"Account {self.description} no updates necessary for {hostname}"
            )
            return False
        return False

    def _request_token(self):
        private_key = self.settings.get('password')
        login = self.settings.get('username')
        label = "DDNS-OPNsense"
        request_body = json.dumps({
            "login": login,
            "nonce": self._get_nonce(),
            "read_only": False,
            "expiration_time": "30 seconds",
            "label": label,
            "global_key": True
        }).encode("ascii")

        private_key_obj = cryptography.hazmat.primitives.serialization.load_pem_private_key(
            private_key.encode("ascii"), password=None)
        signature = base64.b64encode(private_key_obj.sign(
            request_body,
            cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
            cryptography.hazmat.primitives.hashes.SHA512()
        ))

        response = requests.post(
            f"https://{self._services[self.settings.get('service')]}/v6/auth",
            data=request_body,
            headers={"Content-Type": "application/json", "Signature": signature},
            timeout=10
        )
        response.raise_for_status()
        return response.json()["token"]

    def _request_get(self, endpoint, token):
        url = f"https://{self._services[self.settings.get('service')]}/v6/{endpoint}"
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        response.raise_for_status()
        return response.json()

    def _request_patch(self, endpoint, token, data):
        url = f"https://{self._services[self.settings.get('service')]}/v6/{endpoint}"
        response = requests.patch(
            url,
            data=json.dumps(data).encode("ascii"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            },
            timeout=10
        )
        response.raise_for_status()

    def _get_nonce(self):
        import secrets
        return secrets.token_hex(16)