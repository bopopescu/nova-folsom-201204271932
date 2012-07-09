from nova import flags
from nova import log as logging
from nova import exception

from nova.virt.phy import vif_driver
from nova.virt.phy.nec.vifinfo_client import VIFINFOClient

from webob import exc

FLAGS = flags.FLAGS

LOG = logging.getLogger(__name__)


class NECVIFDriver(vif_driver.PhyVIFDriver):

    def _after_plug(self, instance, network, mapping, pif):
        client = VIFINFOClient(FLAGS.quantum_connection_host, FLAGS.quantum_connection_port)
        client.create_vifinfo(mapping['vif_uuid'], pif.datapath_id, pif.port_no)

    def _after_unplug(self, instance, network, mapping, pif):
        client = VIFINFOClient(FLAGS.quantum_connection_host, FLAGS.quantum_connection_port)
        try:
            client.delete_vifinfo(mapping['vif_uuid'])
        except (exception.Error, exc.HTTPNotFound, exc.HTTPInternalServerError), e:
            LOG.warn("client.delete_vifinfo(%s) is failed. (unplugging is continued): %s", mapping['vif_uuid'], e)

