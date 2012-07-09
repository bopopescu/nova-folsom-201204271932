# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 NTT DOCOMO, INC. 
# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""Defines interface for DB access.

The underlying driver is loaded as a :class:`LazyPluggable`.

Functions in this module are imported into the nova.virt.baremetal.bmdb namespace.
Call these functions from nova.virt.baremetal.bmdb namespace, not the
nova.virt.baremetal.bmdb.baremetal_api namespace.

All functions in this module return objects that implement a dictionary-like
interface. Currently, many of these objects are sqlalchemy objects that
implement a dictionary interface. However, a future goal is to have all of
these objects be simple dictionaries.


**Related Flags**

:baremetal_db_backend:  string to lookup in the list of LazyPluggable backends.
              `sqlalchemy` is the only supported backend right now.

:baremetal_sql_connection:  string specifying the sqlalchemy connection to use, like:
                  `sqlite:///var/lib/nova/nova.sqlite`.

"""

""" start add by NTT DOCOMO """

from nova import flags
from nova.openstack.common import cfg
from nova import utils


db_opts = [
    cfg.StrOpt('baremetal_db_backend',
               default='sqlalchemy',
               help='The backend to use for db'),
    ]

FLAGS = flags.FLAGS
FLAGS.register_opts(db_opts)

IMPL = utils.LazyPluggable('baremetal_db_backend',
                           sqlalchemy='nova.virt.baremetal.bmdb.sqlalchemy.baremetal_api')

def phy_host_get_all(context):
    return IMPL.phy_host_get_all(context)


def phy_host_get_all_sorted(context):
    return IMPL.phy_host_get_all_sorted(context)


def phy_host_get(context, phy_host_id, session=None):
    return IMPL.phy_host_get(context, phy_host_id)


def phy_host_get_all_by_service_id(context, service_id, session=None):
    return IMPL.phy_host_get_all_by_service_id(context, service_id)


def phy_host_get_by_pxe_mac_address(context, pxe_mac_address, session=None):
    return IMPL.phy_host_get_by_pxe_mac_address(context, pxe_mac_address)


def phy_host_get_by_ipmi_address(context, ipmi_address, session=None):
    return IMPL.phy_host_get_by_ipmi_address(context, ipmi_address)


def phy_host_get_by_instance_id(context, instance_id, session=None):
    return IMPL.phy_host_get_by_instance_id(context, instance_id)


def phy_host_create(context, values):
    return IMPL.phy_host_create(context, values)


def phy_host_destroy(context, phy_host_id):
    return IMPL.phy_host_destroy(context, phy_host_id)


def phy_host_update(context, phy_host_id, values):
    return IMPL.phy_host_update(context, phy_host_id, values)


def phy_pxe_ip_create(context, address, server_address, service_id):
    return IMPL.phy_pxe_ip_create(context, address, server_address, service_id)


def phy_pxe_ip_get_all(context):
    return IMPL.phy_pxe_ip_get_all(context)


def phy_pxe_ip_get(context, ip_id, session=None):
    return IMPL.phy_pxe_ip_get(context, ip_id, session)


def phy_pxe_ip_get_by_phy_host_id(context, phy_host_id, session=None):
    return IMPL.phy_pxe_ip_get_by_phy_host_id(context, phy_host_id, session)


def phy_pxe_ip_associate(context, phy_host_id):
    return IMPL.phy_pxe_ip_associate(context, phy_host_id)


def phy_pxe_ip_disassociate(context, phy_host_id):
    return IMPL.phy_pxe_ip_disassociate(context, phy_host_id)
    

def phy_interface_get(context, if_id, session=None):
    return IMPL.phy_interface_get(context, if_id, session)


def phy_interface_get_all(context, session=None):
    return IMPL.phy_interface_get_all(context, session)


def phy_interface_destroy(context, if_id):
    return IMPL.phy_interface_destroy(context, if_id)


def phy_interface_create(context, phy_host_id, address, datapath_id, port_no):
    return IMPL.phy_interface_create(context, phy_host_id, address, datapath_id, port_no)


def phy_interface_set_vif_uuid(context, if_id, vif_uuid):
    return IMPL.phy_interface_set_vif_uuid(context, if_id, vif_uuid)


def phy_interface_get_by_vif_uuid(context, vif_uuid):
    return IMPL.phy_interface_get_by_vif_uuid(context, vif_uuid)


def phy_interface_get_all_by_phy_host_id(context, phy_host_id):
    return IMPL.phy_interface_get_all_by_phy_host_id(context, phy_host_id)


def phy_deployment_create(context, key, image_path, pxe_config_path, root_mb, swap_mb):
    return IMPL.phy_deployment_create(context, key, image_path, pxe_config_path, root_mb, swap_mb)


def phy_deployment_get(context, dep_id, session=None):
    return IMPL.phy_deployment_get(context, dep_id, session)


def phy_deployment_destroy(context, dep_id):
    return IMPL.phy_deployment_destroy(context, dep_id)

""" end add by NTT DOCOMO """

