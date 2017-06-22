import datetime
import logging

from logic import db

from HostController.settings import CFG

if __name__ == "__main__":
    CFG.bind_host_port=9000
    CFG.bind_host_address="0.0.0.0"
    logging.info("Installer Analyzer Host Starting: starting app manager.")
    logging.warn("Resetting the whole DB")

    # Clear all
    db.jobmanager._erase()

    # Reset the DB status
    db.jobmanager.reset()

    # Put a test installer
    aggregator = db.jobmanager.get_or_create_aggregator(
        name="filehippo",
        url="http://filehippo.com"
    )

    current_test_bed = db.jobmanager._get_or_create_testbed(mode='virtualized',
                                                            hypervisor='virtualbox',
                                                            os='Windows7',
                                                            os_arch='x86',
                                                            vm_timeout=CFG.vm_run_timeout,
                                                            installer_timeout=900000)

    """
    db.jobmanager.create_job(path="C:\\VMs\\InstallerSources\\1460105348.77\\advanced-systemcare-setup.exe",
                             aggregator=aggregator,
                             downlink="http://files.downloadnow.com/s/software/14/50/56/43/avast_free_antivirus_setup_online.exe?token=1460141310_e75e4d5c0f484a29939fac8dcceac341&fileName=avast_free_antivirus_setup_online.exe",
                             downdate=datetime.datetime.utcnow()
                             )

    db.jobmanager.create_job(path="C:\\users\\webking\\desktop\\3DMark_Vantage_v113_installer.exe",
                             aggregator=aggregator,
                             downlink="http://files.downloadnow.com/s/software/14/50/56/43/avast_free_antivirus_setup_online.exe?token=1460141310_e75e4d5c0f484a29939fac8dcceac341&fileName=avast_free_antivirus_setup_online.exe",
                             downdate=datetime.datetime.utcnow()
                             )



    db.jobmanager.create_job(path="C:\\users\\webking\\desktop\\cuteftp.exe",
                             aggregator=aggregator,
                             downlink="http://files.downloadnow.com/s/software/14/50/56/43/avast_free_antivirus_setup_online.exe?token=1460141310_e75e4d5c0f484a29939fac8dcceac341&fileName=avast_free_antivirus_setup_online.exe",
                             downdate=datetime.datetime.utcnow()
                             )



    db.jobmanager.create_job(path="C:\\users\\webking\\desktop\\ITPx86_1033_8.20.469.0.exe",
                             aggregator=aggregator,
                             downlink="http://files.downloadnow.com/s/software/14/50/56/43/avast_free_antivirus_setup_online.exe?token=1460141310_e75e4d5c0f484a29939fac8dcceac341&fileName=avast_free_antivirus_setup_online.exe",
                             downdate=datetime.datetime.utcnow()
                             )


    """
    db.jobmanager.create_job(path="C:\\Users\\webking\\Desktop\\avg.exe",
                         aggregator=aggregator,
                         downlink="http://files.downloadnow.com/s/software/14/50/56/43/avast_free_antivirus_setup_online.exe?token=1460141310_e75e4d5c0f484a29939fac8dcceac341&fileName=avast_free_antivirus_setup_online.exe",
                         downdate=datetime.datetime.utcnow()
                         )
