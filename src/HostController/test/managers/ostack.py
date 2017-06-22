import time
import unittest
from HostController.settings import CFG
from HostController.managers import machine_manager
from HostController.managers import ostack

class OpenstackManagerTest(unittest.TestCase):
    def test_machine_create(self):

        # Create the manager
        mgr = ostack.OpenStackManager(CFG.os_auth_url,
                                      CFG.os_project_name,
                                      CFG.os_username,
                                      CFG.os_password,
                                      CFG.os_sniffer_image_name,
                                      CFG.os_guest_image_name,
                                      CFG.os_public_network_name,
                                      CFG.os_sniffer_port,
                                      guest_flavor=CFG.os_guest_flavor,
                                      sniffer_flavor=CFG.os_sniffer_flavor)

        g = mgr.create_guest()

        # Check return type
        self.assertIsInstance(g, machine_manager.IGuest, "VboxManager did not requrn a valid IGuestMachine.")
        self.assertIsInstance(g, ostack.OSMachine, "VboxManager did not requrn a valid VBoxMachine.")

        print("Created machine %s " % g.get_id())

        gg = mgr.get_guest_by_mac(g.get_mac())

        self.assertIsInstance(gg, machine_manager.IGuest, "VboxManager did not requrn a valid IGuestMachine.")
        self.assertIsInstance(gg, ostack.OSMachine, "VboxManager did not requrn a valid VBoxMachine.")
        self.assertEqual(gg.get_mac(), g.get_mac(), "Returned machine from VboxService is different from created one.")
        self.assertEqual(gg.get_id(), g.get_id(), "Returned machine from VboxService is different from created one.")
        self.assertIs(gg.get_manager(), g.get_manager(), "Returned machine from VboxService is different from created one.")

    def test_machine_start(self):
        mgr = ostack.OpenStackManager(CFG.os_auth_url,
                                      CFG.os_project_name,
                                      CFG.os_username,
                                      CFG.os_password,
                                      CFG.os_sniffer_image_name,
                                      CFG.os_guest_image_name,
                                      CFG.os_public_network_name,
                                      CFG.os_sniffer_port,
                                      guest_flavor=CFG.os_guest_flavor,
                                      sniffer_flavor=CFG.os_sniffer_flavor)
        g = mgr.create_guest()
        mgr.start_guest(g)

        # Wait a bit and check it is running correctly.
        time.sleep(15)

        self.assertEqual(mgr.get_machine_state(g), machine_manager.MachineState.running)

    def test_machine_batch(self):
        mgr = ostack.OpenStackManager(CFG.os_auth_url,
                                      CFG.os_project_name,
                                      CFG.os_username,
                                      CFG.os_password,
                                      CFG.os_sniffer_image_name,
                                      CFG.os_guest_image_name,
                                      CFG.os_public_network_name,
                                      CFG.os_sniffer_port,
                                      guest_flavor=CFG.os_guest_flavor,
                                      sniffer_flavor=CFG.os_sniffer_flavor)
        mgr.create_batch(2)

    def test_machine_life_cycle(self):
        mgr = ostack.OpenStackManager(CFG.os_auth_url,
                                      CFG.os_project_name,
                                      CFG.os_username,
                                      CFG.os_password,
                                      CFG.os_sniffer_image_name,
                                      CFG.os_guest_image_name,
                                      CFG.os_public_network_name,
                                      CFG.os_sniffer_port,
                                      guest_flavor=CFG.os_guest_flavor,
                                      sniffer_flavor=CFG.os_sniffer_flavor)

        # Create the machine
        g = mgr.create_guest()

        gid = g.get_id()

        # Start it
        mgr.start_guest(g)

        # Wait a bit and check it is running correctly.
        time.sleep(15)
        self.assertEqual(mgr.get_machine_state(g), machine_manager.MachineState.running)

        # Stop it
        mgr.stop_guest(g)
        time.sleep(3)
        self.assertEqual(mgr.get_machine_state(g), machine_manager.MachineState.stopped)

        # Delete it
        mgr.delete_guest(g)
        for m in mgr.list_guests():
            self.assertNotEqual(gid, m.get_id())

    def test_prepare(self):
        from HostController.settings import CFG
        mgr = ostack.OpenStackManager(CFG.os_auth_url,
                                      CFG.os_project_name,
                                      CFG.os_username,
                                      CFG.os_password,
                                      CFG.os_sniffer_image_name,
                                      CFG.os_guest_image_name,
                                      CFG.os_public_network_name,
                                      CFG.os_sniffer_port,
                                      guest_flavor=CFG.os_guest_flavor,
                                      sniffer_flavor=CFG.os_sniffer_flavor)
        mgr.prepare()
        vms = mgr.list_guests()
        self.assertGreaterEqual(len(vms), mgr._n_workers, "Prepare method did not spawn enough VMS.")

if __name__ == '__main__':
    unittest.main()
