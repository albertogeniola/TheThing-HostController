# HostController Agent

The HostController Agent consists in a software module running on a HostController node.
Each HostController Agent is assigned a certain number of Sandboxes (Guests). The lifecycle of such guests is handled by the HostController, via specific APIs (Virtualbox SDK / Openstack SDK / Arduinos for bare metal).

In general, we can summarize the behavior of a HostController Agent as the following:

 1. Create Sniffer and guests via API offered by underlying Hypervisor (only if virtualization is used)
 1. Start the sniffer machine and configure it once it's running via its webservice interface
 1. Start the Guests
 1. Serve requests incoming from guests
    1. Poll the server for new jobs
    1. Serve the job to the guest
    1. Receive the outcome of the analysis
    1. Store the result into the central db
    1. Revert the Guest

## Installation
The HostController agent is developed in pure Python 2.7 and has been tested in both Linux Ubuntu 16.04 LTS 64bit and Windows Server 2012 64 bit.
The installation of the HostController Agent is as simple as installing a normal Python package. However, the user has to setup the Central database and the hypervisor module before installing the HostController Agent. Such operations are described in details in the [Introduction](https://bitbucket.org/albertogeniola/thething/overview).

The mere installation of the only HostController agent's binaries is straightforward, and is described below.

### Windows
First, let's clone the git repository of HostController Agent

```
   C:\> git clone https://github.com/albertogeniola/HostController1.1_python.git
```

Now we need to build the distributable version and install it via PIP command.
```
   C:\> cd HostController1.1_python
   C:\> C:\InstallAnalyzer\scripts\python setup.py sdist
   C:\> cd dist
   C:\> C:\InstallAnalyzer\scripts\pip install HostController-0.1.zip
```


### Linux
Let's download the HostController Agent binaries from the official git repository.

```
    $ cd /home/ubuntu
    $ git clone https://github.com/albertogeniola/HostController1.1_python.git
```

Now let's build and install those binaries into our virtualenv
```
    $ cd /home/ubuntu
    $ cd HostController1.1_python
    $ /home/ubuntu/InstallAnalyzer/bin/python2.7 setup.py sdist
    $ sudo /home/ubuntu/InstallAnalyzer/bin/pip2.7 install dist/HostController-0.1.tar.gz --upgrade
```
