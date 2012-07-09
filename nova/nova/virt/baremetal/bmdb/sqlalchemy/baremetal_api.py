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

"""Implementation of SQLAlchemy backend."""

""" start add by NTT DOCOMO """

from nova import exception
from nova import flags
from nova import utils
from nova import log as logging
from nova.virt.baremetal.bmdb.sqlalchemy import baremetal_models
from nova.virt.baremetal.bmdb.sqlalchemy.baremetal_session import get_session
from sqlalchemy import and_
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import joinedload_all
from sqlalchemy.sql import func
from sqlalchemy.sql.expression import asc
from sqlalchemy.sql.expression import desc
from sqlalchemy.sql.expression import literal_column

from nova.db.sqlalchemy.api import require_admin_context
from nova.db.sqlalchemy.api import is_user_context

FLAGS = flags.FLAGS

LOG = logging.getLogger(__name__)

def model_query(context, *args, **kwargs):
    """Query helper that accounts for context's `read_deleted` field.

    :param context: context to query under
    :param session: if present, the session to use
    :param read_deleted: if present, overrides context's read_deleted field.
    :param project_only: if present and context is user-type, then restrict
            query to match the context's project_id.
    """
    session = kwargs.get('session') or get_session()
    read_deleted = kwargs.get('read_deleted') or context.read_deleted
    project_only = kwargs.get('project_only')

    query = session.query(*args)

    if read_deleted == 'no':
        query = query.filter_by(deleted=False)
    elif read_deleted == 'yes':
        pass  # omit the filter to include deleted and active
    elif read_deleted == 'only':
        query = query.filter_by(deleted=True)
    else:
        raise Exception(
                _("Unrecognized read_deleted value '%s'") % read_deleted)

    if project_only and is_user_context(context):
        query = query.filter_by(project_id=context.project_id)

    return query

    
@require_admin_context
def phy_host_get_all(context, session=None):
    query = model_query(context, baremetal_models.PhyHost, read_deleted="no", session=session)
    return query.all()


@require_admin_context
def phy_host_get_all_sorted(context, session=None):
    query = model_query(context, baremetal_models.PhyHost, read_deleted="no", session=session).\
                   order_by('cpus').\
                   order_by('memory_mb').\
                   order_by('local_gb')
    return query.all()


@require_admin_context
def phy_host_get_all_by_service_id(context, service_id, session=None):
    query = model_query(context, baremetal_models.PhyHost, read_deleted="no", session=session).\
                   filter_by(service_id=service_id)
    return query.all()


@require_admin_context
def phy_host_get(context, phy_host_id, session=None):
    result = model_query(context, baremetal_models.PhyHost, read_deleted="no", session=session).\
                     filter_by(id=phy_host_id).\
                     first()
    return result


@require_admin_context
def phy_host_get_by_pxe_mac_address(context, pxe_mac_address, session=None):
    result = model_query(context, baremetal_models.PhyHost, read_deleted="no", session=session).\
                     filter_by(pxe_mac_address=pxe_mac_address).\
                     first()
    return result


@require_admin_context
def phy_host_get_by_ipmi_address(context, ipmi_address, session=None):
    result = model_query(context, baremetal_models.PhyHost, read_deleted="no", session=session).\
                     filter_by(ipmi_address=ipmi_address).\
                     first()
    return result


@require_admin_context
def phy_host_get_by_instance_id(context, instance_id, session=None):
    result = model_query(context, baremetal_models.PhyHost, read_deleted="no", session=session).\
                     filter_by(instance_id=instance_id).\
                     first()
    return result


@require_admin_context
def phy_host_create(context, values, session=None):
    if not session:
        session = get_session()
    with session.begin():
        phy_host_ref = baremetal_models.PhyHost()
        phy_host_ref.update(values)
        phy_host_ref.save(session=session)
        return phy_host_ref


@require_admin_context
def phy_host_update(context, phy_host_id, values, session=None):
    if not session:
        session = get_session()
    with session.begin():
        phy_host_ref = phy_host_get(context, phy_host_id, session=session)
        phy_host_ref.update(values)
        phy_host_ref.save(session=session)


@require_admin_context
def phy_host_destroy(context, phy_host_id, session=None):
    model_query(context, baremetal_models.PhyHost, session=session).\
                filter_by(id=phy_host_id).\
                update({'deleted': True,
                        'deleted_at': utils.utcnow(),
                        'updated_at': literal_column('updated_at')})


@require_admin_context
def phy_pxe_ip_get_all(context, session=None):
    query = model_query(context, baremetal_models.PhyPxeIp, read_deleted="no", session=session)
    return query.all()


@require_admin_context
def phy_pxe_ip_create(context, address, server_address, service_id, session=None):
    ref = model_query(context, baremetal_models.PhyPxeIp, read_deleted="no", session=session).\
                     filter_by(address=address).\
                     filter_by(service_id=service_id).\
                     first()
    if not ref:
        ref = baremetal_models.PhyPxeIp()
        ref.address = address
        ref.server_address = server_address
        ref.service_id = service_id
        ref.save(session=session)
    else:
        if ref.server_addess != server_address:
            raise exception.Error('address exists, but server_address is not same')
    return ref.id


@require_admin_context
def phy_pxe_ip_get(context, ip_id, session=None):
    ref = model_query(context, baremetal_models.PhyPxeIp, read_deleted="no", session=session).\
                     filter_by(id=ip_id).\
                     first()
    return ref


@require_admin_context
def phy_pxe_ip_get_by_phy_host_id(context, phy_host_id, session=None):
    ref = model_query(context, baremetal_models.PhyPxeIp, read_deleted="no", session=session).\
                     filter_by(phy_host_id=phy_host_id).\
                     first()
    return ref


@require_admin_context
def phy_pxe_ip_associate(context, phy_host_id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        ph_ref = phy_host_get(context, phy_host_id, session=session)
        if not ph_ref:
            raise exception.Error(host=phy_host_id)
        ip_ref = model_query(context, baremetal_models.PhyPxeIp, read_deleted="no", session=session).\
                         filter_by(service_id=ph_ref.service_id).\
                         filter_by(phy_host_id=ph_ref.id).\
                         first()
        if ip_ref:
            return ip_ref.id
        ip_ref = model_query(context, baremetal_models.PhyPxeIp, read_deleted="no", session=session).\
                         filter_by(service_id=ph_ref.service_id).\
                         filter_by(phy_host_id=None).\
                         with_lockmode('update').\
                         first()
        if not ip_ref:
            raise exception.Error()
        ip_ref.phy_host_id = phy_host_id
        session.add(ip_ref)
        return ip_ref.id


@require_admin_context
def phy_pxe_ip_disassociate(context, phy_host_id, session=None):
    if not session:
        session = get_session()
    with session.begin():
        ip = phy_pxe_ip_get_by_phy_host_id(context, phy_host_id, session=session)
        if ip:
            ip.phy_host_id = None
            ip.save(session=session)
    

@require_admin_context
def phy_interface_get(context, if_id, session=None):
    result = model_query(context, baremetal_models.PhyInterface, read_deleted="no", session=session).\
                     filter_by(id=if_id).\
                     first()
    return result


def phy_interface_get_all(context, session=None):
    query = model_query(context, baremetal_models.PhyInterface, read_deleted="no", session=session)
    return query.all()


@require_admin_context
def phy_interface_destroy(context, if_id, session=None):
    model_query(context, baremetal_models.PhyInterface, read_deleted="no", session=session).\
                filter_by(id=if_id).\
                update({'deleted': True,
                        'deleted_at': utils.utcnow(),
                        'updated_at': literal_column('updated_at')})


@require_admin_context
def phy_interface_create(context, phy_host_id, address, datapath_id, port_no, session=None):
    if not session:
        session = get_session()
    with session.begin():
        ref = baremetal_models.PhyInterface()
        ref.phy_host_id = phy_host_id
        ref.address = address
        ref.datapath_id = datapath_id
        ref.port_no = port_no
        ref.save(session=session)
        return ref.id


@require_admin_context
def phy_interface_set_vif_uuid(context, if_id, vif_uuid, session=None):
    if not session:
        session = get_session()
    with session.begin():
        ref = model_query(context, baremetal_models.PhyInterface, read_deleted="no", session=session).\
                         filter_by(id=if_id).\
                         with_lockmode('update').\
                         first()
        if not ref:
            raise exception.Error()
        ref.vif_uuid = vif_uuid
        session.add(ref)


@require_admin_context
def phy_interface_get_by_vif_uuid(context, vif_uuid, session=None):
    result = model_query(context, baremetal_models.PhyInterface, read_deleted="no", session=session).\
                filter_by(vif_uuid=vif_uuid).\
                first()
    return result


@require_admin_context
def phy_interface_get_all_by_phy_host_id(context, phy_host_id, session=None):
    result = model_query(context, baremetal_models.PhyInterface, read_deleted="no", session=session).\
                 filter_by(phy_host_id=phy_host_id).\
                 all()
    return result


@require_admin_context
def phy_deployment_create(context, key, image_path, pxe_config_path, root_mb, swap_mb, session=None):
    if not session:
        session = get_session()
    with session.begin():
        ref = baremetal_models.PhyDeployment()
        ref.key = key
        ref.image_path = image_path
        ref.pxe_config_path = pxe_config_path
        ref.root_mb = root_mb
        ref.swap_mb = swap_mb
        ref.save(session=session)
        return ref.id


@require_admin_context
def phy_deployment_get(context, dep_id, session=None):
    result = model_query(context, baremetal_models.PhyDeployment, read_deleted="no", session=session).\
                     filter_by(id=dep_id).\
                     first()
    return result


@require_admin_context
def phy_deployment_destroy(context, dep_id, session=None):
    model_query(context, baremetal_models.PhyDeployment, session=session).\
                filter_by(id=dep_id).\
                update({'deleted': True,
                        'deleted_at': utils.utcnow(),
                        'updated_at': literal_column('updated_at')})


""" end add by NTT DOCOMO """
