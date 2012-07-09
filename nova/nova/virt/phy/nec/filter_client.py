# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 NTT DOCOMO, INC. 
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

""" start add by NTT DOCOMO """

from nova.network.quantum.client import Client
from nova.network.quantum.client import api_call


class FilterClient(Client):
    """A base client class - derived from Glance.BaseClient"""

    """Action query strings"""
    filters_path = "/networks/%s/filters"
    filter_path = "/networks/%s/filters/%s"

    def __init__(self, host="127.0.0.1", port=9696, use_ssl=False, tenant=None,
                 format="xml", testing_stub=None, key_file=None,
                 cert_file=None, logger=None):
        """Creates a new client to some service.

        :param host: The host where service resides
        :param port: The port where service resides
        :param use_ssl: True to use SSL, False to use HTTP
        :param tenant: The tenant ID to make requests with
        :param format: The format to query the server with
        :param testing_stub: A class that stubs basic server methods for tests
        :param key_file: The SSL key file to use if use_ssl is true
        :param cert_file: The SSL cert file to use if use_ssl is true
        """
        super(FilterClient, self).__init__(host, port, use_ssl, tenant, format, testing_stub, key_file, cert_file, logger)

    @api_call
    def list_filters(self, tenant_id, network_id):
        """Fetches a list of all filters for a network"""
        self.tenant = tenant_id
        return self.do_request("GET", self.filters_path % (network_id))

    @api_call
    def show_filter_details(self, tenant_id, network_id, filter_id):
        """Fetches the details of a certain filter"""
        self.tenant = tenant_id
        return self.do_request("GET", self.filter_path % (network_id, filter_id))

    @api_call
    def create_filter(self, tenant_id, network_id, body=None):
        """Creates a new filter"""
        body = self.serialize(body)
        self.tenant = tenant_id
        return self.do_request("POST", self.filters_path % (network_id), body=body)

    @api_call
    def update_filter(self, tenant_id, network_id, filter_id, body=None):
        """Updates a filter"""
        body = self.serialize(body)
        self.tenant = tenant_id
        return self.do_request("PUT", self.filter_path % (network_id, filter_id), body=body)

    @api_call
    def delete_filter(self, tenant_id, network_id, filter_id):
        """Deletes the specified filter"""
        self.tenant = tenant_id
        return self.do_request("DELETE", self.filter_path % (network_id, filter_id))

""" end add by NTT DOCOMO """