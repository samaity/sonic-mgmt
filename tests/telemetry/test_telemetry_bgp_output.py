import re
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.telemetry.test_telemetry import get_list_stdout, verify_telemetry_dockerimage, setup_telemetry_forpyclient
from tests.telemetry.test_telemetry import check_telemetry_daemon_status, get_telemetry_daemon_states

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

# Globals
ADMIN_DOWN = '1' # AdminStatus(1): Down
ADMIN_UP = '2'   # AdminStatus(2): Up

@pytest.fixture(scope="module")
def common_setup(duthost, ptfhost):

    logging.info("########### Setup for BGP Table outout via Telemetry testing ###########")

    docker_present = verify_telemetry_dockerimage(duthost)
    if not docker_present:
        pytest.skip("docker-sonic-telemetry is not part of the image")

    logger.info('start telemetry output for BGP_TABLE testing')
    setup_telemetry_forpyclient(duthost)

    # wait till telemetry is restarted
    pytest_assert(wait_until(100, 10, duthost.is_service_fully_started, "telemetry"), "TELEMETRY not started")
    logger.info('telemetry process restarted. Now run pyclient on ptfdocker')
    dut_ip = duthost.setup()['ansible_facts']['ansible_eth0']['ipv4']['address']

    # pyclient should be available on ptfhost. If not fail pytest.
    file_exists = ptfhost.stat(path="/gnxi/gnmi_cli_py/py_gnmicli.py")
    pytest_assert(file_exists["stat"]["exists"] is True)

    logging.info("Check telemetry daemon status")
    pytest_assert(check_telemetry_daemon_status(duthost), "Not all telemetry daemons running.")

    logging.info("########### Done setup BGP Table outout via Telemetry testing ###########")
    yield dut_ip

# Test functions
def test_telemetry_bgp_table(common_setup, duthost, ptfhost):
    """ Run pyclient from ptfdocker and show gnmi server outputself.
    """
    dut_ip = common_setup
    cmd = 'python /gnxi/gnmi_cli_py/py_gnmicli.py -g -t {0} -p 50051 -m get -x BGP_TABLE/ -xt STATE_DB -o "ndastreamingservertest"'.format(dut_ip)
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    logger.info("BGP Table output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)

def test_telemetry_all_bgp_keys(common_setup, duthost, ptfhost):
    """ Test whether all  bgp keys avaialable in STATE DB using gnmi get and server outputself.
    """
    dut_ip = common_setup

    # Gather bgp_facts about all bgp neighbors
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    logger.info(bgp_facts)

    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are established
        assert v['state'] == 'established'
        cmd = 'python /gnxi/gnmi_cli_py/py_gnmicli.py -g -t {0} -p 50051 -m get -x BGP_TABLE/{1} -xt STATE_DB -o "ndastreamingservertest"'.format(dut_ip, k)
        show_gnmi_out = ptfhost.shell(cmd)['stdout']
        logger.info("BGP Table output")
        result = str(show_gnmi_out)
        logger.info(result)

        """ Check whether all BGP metrics available under BGP_TABLE in STATE_DB.
            Metrics are:  1. BgpPeerLocalAddr
                          2. BgpPrefixInPrefixesAccepted
                          3. BgpPeerDescription
                          4. BgpPeerAdminStatus
                          5. BgpPeerState
                          6. BgpPeerEstablishedTime
                          7. BgpPeerInTotalMessages
        """
        local_addr_match = re.search("BgpPeerLocalAddr", result)
        pytest_assert(local_addr_match is not None, "BgpPeerLocalAddr not found in gnmi_output for peer {}".format(k))

        in_prefix_match = re.search("BgpPrefixInPrefixesAccepted", result)
        pytest_assert(in_prefix_match is not None, "BgpPrefixInPrefixesAccepted not found in gnmi_output for peer {}".format(k))

        peer_desc_match = re.search("BgpPeerDescription", result)
        pytest_assert(peer_desc_match is not None, "BgpPeerDescription not found in gnmi_output for peer {}".format(k))

        peer_admin_status_match = re.search("BgpPeerAdminStatus", result)
        pytest_assert(peer_admin_status_match is not None, "BgpPeerAdminStatus not found in gnmi_output for peer {}".format(k))

        peer_state_match = re.search("BgpPeerState", result)
        pytest_assert(peer_state_match is not None, "BgpPeerState not found in gnmi_output for peer {}".format(k))

        peer_est_time_match = re.search("BgpPeerEstablishedTime", result)
        pytest_assert(peer_est_time_match is not None, "BgpPeerEstablishedTime not found in gnmi_output for peer {}".format(k))

        peer_In_tot_msz_match = re.search("BgpPeerInTotalMessages", result)
        pytest_assert(peer_In_tot_msz_match is not None, "BgpPeerInTotalMessages not found in gnmi_output for peer {}".format(k))

        # Compare bgp Local Addr generating from FRR, using the VTYSH command line
        # to the peer Local address stored in BGP_TABLE for each neighbor under STATE DB.
        peerLocaladdr_match = re.search("BgpPeerLocalAddr\":\s+\"(.+)\"", result)
        if peerLocaladdr_match:
            peerLocaladdr_in_state_db = peerLocaladdr_match.group(1)
            logger.info(peerLocaladdr_in_state_db)
            pytest_assert(peerLocaladdr_in_state_db == k,
                          "Target BGP peer local address {} does match with expected one : {}".format(peerLocaladdr_in_state_db, k))

        # Compare bgp peer description generating from FRR, using the VTYSH command line
        # to the peer description stored in BGP_TABLE for each neighbor under STATE DB.
        peerDesc_match = re.search("BgpPeerDescription\":\s+\"(\w+)+\"", result)
        if peerDesc_match:
            peerDesc_in_state_db = peerDesc_match.group(1).upper()
            logger.info(peerDesc_in_state_db)
            pytest_assert(peerDesc_in_state_db == v['description'],
			  "Target peer description {} does match with expected one : {}".format(peerDesc_in_state_db, v['description']))

        # Compare bgp peer ADMIN status generating from FRR,using the VTYSH command line
        # to the peer ADMIN status stored in BGP_TABLE for each neighbor under STATE DB.
        peerAdmin_status_match = re.search("BgpPeerAdminStatus\":\s+\"(\w+)+\"", result)
        if peerAdmin_status_match:
            peerAdmin_status_in_state_db = peerAdmin_status_match.group(1).lower()
            logger.info(peerAdmin_status_in_state_db)
            peer_admin_status = 'up' if peerAdmin_status_in_state_db  == ADMIN_UP else 'down'
            pytest_assert(peer_admin_status == v['admin'],
                          "Target peer state {} does match with expected one : {}".format(peer_admin_status, v['admin']))

        # Compare bgp peer state generating from FRR, using the VTYSH command line
        # to the peer state stored in BGP_TABLE for each neighbor under STATE DB.
        peerState_match = re.search("BgpPeerState\":\s+\"(\w+)+\"", result)
        if peerState_match:
            peerState_in_state_db = peerState_match.group(1).lower()
            logger.info(peerState_in_state_db)
            pytest_assert(peerState_in_state_db == v['state'],
                          "Target peer state {} does match with expected one : {}".format(peerState_in_state_db, v['state']))
