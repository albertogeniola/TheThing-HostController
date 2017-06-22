__author__ = 'Alberto Geniola'

from logic import app

from HostController.settings import CFG

if __name__ == "__main__":

    # Special network setup for this test
    CFG.bind_host_address = CFG.bind_host_port
    CFG.bind_host_port = CFG.bind_host_port

    app.manager = app.Manager()
    app.manager.start_server()