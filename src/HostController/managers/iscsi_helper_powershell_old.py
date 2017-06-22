import os
import re
import web
import logging
import sys
import json
from subprocess import Popen, PIPE

# TODO change handler to log on a file
l = logging.getLogger("webCTRL")
l.setLevel(logging.DEBUG)
hdlr = logging.StreamHandler(stream=sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
hdlr.setLevel(logging.INFO)
l.addHandler(hdlr)

DEVNULL = open(os.devnull, 'wb')
mac_re = re.compile("^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$")

IPXE_TEMPLATE = "#!ipxe\nsanboot iscsi:{ip}::::{iqn}"

BASE_DISK_PATH = "C:\\users\\administrator\\desktop\\base_disk.vhd"
DISK_PATH_DIR = "C:\\users\\administrator\\desktop\\"

CREATE_ISCSI_CMD = 'New-IscsiServerTarget -TargetName {name} -InitiatorId @("MACAddress:{mac}")'
GET_ISCSI_CMD = 'Get-IscsiServerTarget {name}'
REMOVE_ISCSI_CMD = 'Remove-IscsiServerTarget -TargetName {name}'
CREATE_ISCSI_VHD = 'New-IscsiVirtualDisk -Path \"{path}\" -ParentPath \"{parent_path}\" '
REMOVE_ISCSI_VHD = 'Remove-IscsiVirtualDisk -Path {path}'
MAP_VHD_TARGET = 'Add-IscsiVirtualDiskTargetMapping -TargetName \"{target_name}\" -Path \"{vhd_path}\" '
UNMAP_VHD_TARGET = 'Remove-IscsiVirtualDiskTargetMapping -TargetName \"{target_name}\" -Path \"{vhd_path}\" '
GET_ISCSI_SERVER_TARGET = 'Get-IscsiServerTarget -TargetName \"{target_name}\" | Select-Object -Property TargetIqn,Status,LunMappings,TargetName | Format-List'


def _create_iscsi_target(name, mac_addr):
    """
    Creates a new iscsi target named with name. Returns True on success, False otherwise.
    :param name:
    :return:
    """
    # Check if the iscsi exists.
    cmd = GET_ISCSI_CMD.format(name=name)
    p = Popen(['powershell', '-Command', cmd], shell=True, stdout=DEVNULL, stderr=DEVNULL)
    p.communicate()

    if p.returncode == 0:
        # The target exists already. Remove it.
        cmd = REMOVE_ISCSI_CMD.format(name=name)
        p = Popen(['powershell', '-Command', cmd], shell=True, stdout=DEVNULL, stderr=DEVNULL)
        p.communicate()

    # Otherwise let's create it.
    addr = mac_addr.replace(":", "-")

    cmd = CREATE_ISCSI_CMD.format(name=name, mac=addr)
    p = Popen(['powershell', '-Command', cmd], shell=True)
    p.communicate()

    return p.returncode == 0


def _remove_iscsi_vhd(vhd_path):
    cmd = REMOVE_ISCSI_VHD.format(path=vhd_path)
    p = Popen(['powershell', '-Command', cmd], shell=True, stdout=DEVNULL, stderr=DEVNULL)
    p.communicate()

    return p.returncode == 0


def _create_diff_vhd(parent_path, path):
    """
    Creates a differencing VHD wrapping the New-IscsiVirtualDisk cmdlet.
    Returns true on success, false on failure.
    :param parent_path:
    :param path:
    :return:
    """
    # Check if the parent exists
    if not os.path.isfile(parent_path):
        raise Exception("The parent VHD file %s does not exist." % parent_path)

    cmd = CREATE_ISCSI_VHD.format(parent_path=parent_path, path=path)
    p = Popen(['powershell', '-Command', cmd], shell=True, stdout=DEVNULL, stderr=DEVNULL)
    p.communicate()
    return p.returncode == 0


def _map_vhd_to_lun_target(target_name, vhd_fname):

    cmd = MAP_VHD_TARGET.format(target_name=target_name, vhd_path=vhd_fname)
    p = Popen(['powershell', '-Command', cmd], shell=True, stdout=DEVNULL, stderr=DEVNULL)
    p.communicate()
    return p.returncode == 0


def _unmap_vhd_to_lun_target(target_name, vhd_fname):

    cmd = UNMAP_VHD_TARGET.format(target_name=target_name, vhd_path=vhd_fname)
    p = Popen(['powershell', '-Command', cmd], shell=True, stdout=DEVNULL, stderr=DEVNULL)
    p.communicate()
    return p.returncode == 0


def _get_iscsi_target_info(target_name):
    cmd = GET_ISCSI_SERVER_TARGET.format(target_name=target_name)
    p = Popen(['powershell', '-Command', cmd], shell=True, stdout=PIPE)
    output, err = p.communicate()
    retcode = p.returncode

    curval = ""
    curkey = ""

    if retcode != 0:
        return None
    else:
        res = dict()

        for l in output.splitlines():
            if l == "":
                if curkey != "":
                    res[curkey] = curval
                    curkey = ""
                    curval = ""
                continue

            if l.startswith(" "):
                curval = curval + l.strip()
            else:
                if curkey != "":
                    res[curkey] = curval
                    curkey = ""
                    curval = ""

                curkey = l.split(":")[0].strip()
                curval = (":".join(l.split(":")[1:])).strip()

    if curkey != "":
        res[curkey] = curval
        curkey = ""
        curval = ""

    # Now parse the LunMappings. PowerShell uses a strange format...
    mappings = []
    line = res.get('LunMappings')
    if line is not None:
        lines = line.strip("{}").split(",")
        tmp = {}
        for l in lines:
            for ll in l.split(";"):
                lvalue = ll.split(":")[0]
                rvalue = ":".join(ll.split(":")[1:]).strip("\"")
                tmp[lvalue.strip()] = rvalue.strip()
        mappings.append(tmp)

    res['LunMappings'] = mappings

    return res


def _calculate_iscsi_params(mac):
    """
    Given a mac address string as input, calculates the iscsi target name and the path of the differencing vhd to be created
    :param mac:
    :return:
    """
    if mac is None:
        raise ValueError("Invalid mac address provided")

    name = mac.lower().strip()

    if not mac_re.match(name):
        raise ValueError("Invalid mac address provided")

    name = name.replace("-","")
    name = name.replace(":","")

    return name, os.path.join(DISK_PATH_DIR, name + ".vhd")


def _compose_ipxe_script(iscsi_server_ip, iqn):
    return str(IPXE_TEMPLATE.format(ip=iscsi_server_ip, iqn=iqn))


class BootManager:
    def GET(self, mac):
        try:
            target_name, vhd_path = _calculate_iscsi_params(mac)

            # Check if there already is an iSCSI target with that name
            info = _get_iscsi_target_info(target_name)
            if info is not None:
                l.info("Found an ISCSI target for this machine: %s" % json.dumps(info))

                # Unmap the vhd-lun
                if _unmap_vhd_to_lun_target(target_name=target_name, vhd_fname=vhd_path):
                    l.info("ISCSI target unmapped correctly.")
                else:
                    l.warn("Could not unmap iSCSI target.")

                # Remove the disk
                if _remove_iscsi_vhd(vhd_path=vhd_path):
                    l.info("Removed VHD mapping.")
                else:
                    l.warn("Failed to remove VHD mapping.")

                if os.path.isfile(vhd_path):
                    l.info("Removing orphan VHD file %s" % vhd_path)
                    try:
                        os.unlink(vhd_path)
                    except Exception:
                        l.warn("Failed to remove file %s" % vhd_path)
                        raise web.internalerror("Could not remove VHD file")

            if not _create_iscsi_target(target_name, mac):
                l.warn("Could not create iscsi target %s" % target_name)
                raise web.internalerror("Could not create ISCSI target")
            else:
                l.info("iSCSI target %s created" % target_name)

            if not _create_diff_vhd(parent_path=BASE_DISK_PATH, path=vhd_path):
                l.warn("Could not create VHD differencing disk.")
                raise web.internalerror("Could not create VHD differencing disk.")
            else:
                l.info("VHD disk %s created" % vhd_path)

            if not _map_vhd_to_lun_target(target_name=target_name, vhd_fname=vhd_path):
                l.warn("Could not map iscsi target %s to vhd %s" % (target_name, vhd_path))
                raise web.internalerror("Could not map target to VHD")
            else:
                l.info("ISCSI target %s mapped to vhd %s" % (target_name, vhd_path))

            info = _get_iscsi_target_info(target_name)

            # Now compose the iPXE script and return it.
            addr = web.ctx.host.split(":")[0]
            res = _compose_ipxe_script(iscsi_server_ip=addr, iqn=info.get('TargetIqn'))

            l.debug("Returning script to the client: %s" % res)

            return res

        except Exception as e:
            raise web.badrequest(message=e.message)


class WebService(web.application):
    def run(self, bind_addr='0.0.0.0', port=8181, *middleware):
        func = self.wsgifunc(*middleware)
        return web.httpserver.runsimple(func, (bind_addr, port))

urls = ('^/boot/(.+)', 'BootManager')

if __name__ == '__main__':
    app = WebService(urls, globals())
    app.run()
