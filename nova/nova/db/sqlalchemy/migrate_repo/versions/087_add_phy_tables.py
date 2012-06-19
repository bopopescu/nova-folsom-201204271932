
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

""" star add by NTT DOCOMO """

from sqlalchemy import Column, Table, MetaData
from sqlalchemy import Integer, DateTime, Boolean, String

from nova import log as logging

meta = MetaData()

phy_hosts = Table('phy_hosts', meta,
        Column('created_at', DateTime(timezone=False)),
        Column('updated_at', DateTime(timezone=False)),
        Column('deleted_at', DateTime(timezone=False)),
        Column('deleted', Boolean(create_constraint=True, name=None)),
        Column('id', Integer(),  primary_key=True, nullable=False),
        Column('cpus', Integer()),
        Column('memory_mb', Integer()),
        Column('local_gb', Integer()),
        Column('ipmi_address',
               String(length=255, convert_unicode=False, assert_unicode=None,
                      unicode_error=None, _warn_on_bytestring=False)),
        Column('ipmi_user',
               String(length=255, convert_unicode=False, assert_unicode=None,
                      unicode_error=None, _warn_on_bytestring=False)),
        Column('ipmi_password',
               String(length=255, convert_unicode=False, assert_unicode=None,
                      unicode_error=None, _warn_on_bytestring=False)),
        Column('service_id', Integer()),
        Column('pxe_mac_address',
               String(length=255, convert_unicode=False, assert_unicode=None,
                      unicode_error=None, _warn_on_bytestring=False)),
        Column('instance_id', Integer()),
        Column('registration_status',
               String(length=16, convert_unicode=False, assert_unicode=None,
                      unicode_error=None, _warn_on_bytestring=False)),
        Column('task_state',
               String(length=255, convert_unicode=False, assert_unicode=None,
                      unicode_error=None, _warn_on_bytestring=False),
               nullable=True),
        Column('pxe_vlan_id', Integer()),
        Column('terminal_port', Integer()))

phy_pxe_ips = Table('phy_pxe_ips', meta,
        Column('created_at', DateTime(timezone=False)),
        Column('updated_at', DateTime(timezone=False)),
        Column('deleted_at', DateTime(timezone=False)),
        Column('deleted', Boolean(create_constraint=True, name=None)),
        Column('id', Integer(),  primary_key=True, nullable=False),
        Column('address',
               String(length=255, convert_unicode=False, assert_unicode=None,
                      unicode_error=None, _warn_on_bytestring=False)),
        Column('service_id', Integer(), nullable=False),
        Column('phy_host_id', Integer(), nullable=True),
        Column('server_address', String(255)))

phy_interfaces = Table('phy_interfaces', meta,
        Column('created_at', DateTime(timezone=False)),
        Column('updated_at', DateTime(timezone=False)),
        Column('deleted_at', DateTime(timezone=False)),
        Column('deleted', Boolean(create_constraint=True, name=None)),
        Column('id', Integer(),  primary_key=True, nullable=False),
        Column('phy_host_id', Integer(), nullable=False),
        Column('address',
               String(length=255, convert_unicode=False, assert_unicode=None,
                      unicode_error=None, _warn_on_bytestring=False)),
        Column('datapath_id',
               String(length=255, convert_unicode=False, assert_unicode=None,
                      unicode_error=None, _warn_on_bytestring=False)),
        Column('port_no', Integer(), nullable=False),
        Column('vif_uuid', String(36)))

phy_deployments = Table('phy_deployments', meta,
        Column('created_at', DateTime(timezone=False)),
        Column('updated_at', DateTime(timezone=False)),
        Column('deleted_at', DateTime(timezone=False)),
        Column('deleted', Boolean(create_constraint=True, name=None)),
        Column('id', Integer(),  primary_key=True, nullable=False),
        Column('key', String(length=255)),
        Column('image_path', String(length=255)),
        Column('pxe_config_path', String(length=255)),
        Column('root_mb', Integer(), nullable=False),
        Column('swap_mb', Integer(), nullable=False) )


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine;
    # bind migrate_engine to your metadata
    meta.bind = migrate_engine

    try:
        phy_hosts.create()
        phy_interfaces.create()
        phy_deployments.create()
        phy_pxe_ips.create()
    except Exception:
        logging.info(repr(phy_hosts))
        logging.exception('Exception while creating table')
        meta.drop_all(tables=[phy_hosts])
        raise


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    phy_deployments.drop()
    phy_interfaces.drop()
    phy_pxe_ips.drop()
    phy_hosts.drop()


""" end add by NTT DOCOMO """
