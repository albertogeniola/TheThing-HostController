import datetime
import unittest
import json
import socket

from HostController.logic import db, app


class InfrastructureTest(unittest.TestCase):
    def test_discover_service(self):
        sa = app.ServerAdvertiser()
        sa.start()
        print("Discover service started on %s:%d" % (sa._addr, sa._port))

        # Test the service.
        msg = {"msg": "DISCOVER"}

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("", 9000))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(json.dumps(msg), ("255.255.255.255", sa._port))

        data, address = s.recvfrom(4096)
        # Check if message is ok. If so, answer back with our address and port.
        msg = json.loads(data)
        if 'msg' in msg and msg.get('msg') == 'HELO':
            port = msg.get('port')
            addr = address[0]

            print("Addr: %s:%d" % (addr, port))

    def test_single_analysis(self):
        # Erase the database and reset its status
        jm = db.JobManager()
        jm._erase()
        jm.reset()

        # Try the analysis of a small and simple installer, such as winzip
        agg = jm.get_or_create_aggregator("test", "NA")
        jm.create_job(path="c:\\users\\alberto geniola\\desktop\\winzip21_downwz.exe",
                      aggregator=agg,
                      downlink="NA",
                      downdate=datetime.datetime.now())

        ctrl = app.AppController()
        ctrl.load()

        # Start the network daemon
        ctrl.start_server()

        # Start all the vms
        ctrl.run_all_machines()

    def test_only_network_services(self):
        # Erase the database and reset its status
        jm = db.JobManager()
        jm._erase()
        jm.reset()

        # Try the analysis of a small and simple installer, such as winzip
        agg = jm.get_or_create_aggregator("test", "NA")
        jm.create_job(path="c:\\users\\alberto geniola\\desktop\\winzip21_downwz.exe",
                      aggregator=agg,
                      downlink="NA",
                      downdate=datetime.datetime.now())

        ctrl = app.AppController()
        ctrl.load()

        # Start the network daemon
        ctrl.start_server()

if __name__ == '__main__':
    unittest.main()
