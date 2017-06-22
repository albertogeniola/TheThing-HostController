import time
import unittest

from HostController.managers import machine_manager
from HostController.managers import vbox


class VboxManagerTest(unittest.TestCase):
    def test_machine_create(self):

        # Create the manager
        mgr = vbox.VBoxManager()

        g = mgr.create_guest()

        # Check return type
        self.assertIsInstance(g, machine_manager.IGuest, "VboxManager did not requrn a valid IGuestMachine.")
        self.assertIsInstance(g, vbox.VBoxMachine, "VboxManager did not requrn a valid VBoxMachine.")

        print("Created machine %s " % g.get_id())

        gg = mgr.get_guest_by_mac(g.get_mac())

        self.assertIsInstance(gg, machine_manager.IGuest, "VboxManager did not requrn a valid IGuestMachine.")
        self.assertIsInstance(gg, vbox.VBoxMachine, "VboxManager did not requrn a valid VBoxMachine.")
        self.assertEqual(gg.get_mac(), g.get_mac(), "Returned machine from VboxService is different from created one.")
        self.assertEqual(gg.get_id(), g.get_id(), "Returned machine from VboxService is different from created one.")
        self.assertIs(gg.get_manager(), g.get_manager(), "Returned machine from VboxService is different from created one.")

    def test_machine_start(self):
        mgr = vbox.VBoxManager()
        g = mgr.create_guest()
        mgr.start_guest(g)

        # Wait a bit and check it is running correctly.
        time.sleep(15)

        self.assertEqual(mgr.get_machine_state(g), machine_manager.MachineState.running)

    def test_machine_batch(self):
        mgr = vbox.VBoxManager()
        mgr.create_batch(2)

    def test_machine_life_cycle(self):
        mgr = vbox.VBoxManager()

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
        mgr = vbox.VBoxManager()
        mgr.prepare()
        vms = mgr.list_guests()
        self.assertGreaterEqual(len(vms), CFG.vbox_workers, "Prepare method did not spawn enough VMS.")

if __name__ == '__main__':
    unittest.main()
