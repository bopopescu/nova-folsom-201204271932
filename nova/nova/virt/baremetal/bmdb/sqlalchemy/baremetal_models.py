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

"""
SQLAlchemy models for baremetal data.
"""

""" start add by NTT DOCOMO """

from sqlalchemy.orm import relationship, backref, object_mapper
from sqlalchemy import Column, Integer, BigInteger, String, schema
from sqlalchemy import ForeignKey, DateTime, Boolean, Text, Float
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.schema import ForeignKeyConstraint

from nova import flags

from nova.db.sqlalchemy import models
from nova.virt.baremetal.bmdb.sqlalchemy import baremetal_session


FLAGS = flags.FLAGS
BASE = declarative_base()


class PhyHost(BASE, models.NovaBase):
    """Represents a running physical compute service on a host."""

    __tablename__ = 'phy_hosts'
    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, nullable=True)
    instance_id = Column(Integer, nullable=True)
    cpus = Column(Integer)
    memory_mb = Column(Integer)
    local_gb = Column(Integer)
    ipmi_address = Column(Text)
    ipmi_user = Column(Text)
    ipmi_password = Column(Text)
    pxe_mac_address = Column(Text)
    registration_status = Column(String(16))
    task_state = Column(String(255))
    pxe_vlan_id = Column(Integer)
    terminal_port = Column(Integer)


class PhyPxeIp(BASE, models.NovaBase):
    __tablename__ = 'phy_pxe_ips'
    id = Column(Integer, primary_key=True)
    address = Column(String(255))
    server_address = Column(String(255))
    service_id = Column(Integer, nullable=False)
    phy_host_id = Column(Integer, ForeignKey('phy_hosts.id'), nullable=True)


class PhyInterface(BASE, models.NovaBase):
    __tablename__ = 'phy_interfaces'
    id = Column(Integer, primary_key=True)
    phy_host_id = Column(Integer, ForeignKey('phy_hosts.id'))
    address = Column(String(255), unique=True)
    datapath_id = Column(String(255))
    port_no = Column(Integer)
    vif_uuid = Column(String(36))


class PhyDeployment(BASE, models.NovaBase):
    __tablename__ = 'phy_deployments'
    id = Column(Integer, primary_key=True)
    key = Column(String(255))
    image_path = Column(String(255))
    pxe_config_path = Column(String(255))
    root_mb = Column(Integer)
    swap_mb = Column(Integer)

def register_models():
    engine = baremetal_session.get_engine()
    BASE.metadata.create_all(engine)

def unregister_models():
    engine = baremetal_session.get_engine()
    BASE.metadata.drop_all(engine)


""" end add by NTT DOCOMO """

