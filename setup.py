from distutils.core import setup

# TODO: this wont work out of the box.
"""
setup(
        name='GuestBootstrapper',
        version='0.1',
        packages=['GuestBootstrapper'],
        package_dir={'GuestBootstrapper': 'src/GuestBootstrapper'},
        package_data={'GuestBootstrapper': ['bootstrapper.conf']},
        entry_points={'console_scripts': ['guest_agent=GuestBootstrapper.Bootstrapper:main']},
        url='',
        license='',
        author='Alberto Geniola',
        author_email='albertogeniola@gmail.com',
        description=''
)
"""
setup(
        name='HostController',
        version='0.1',
        packages=['HostController', 'HostController.admin', 'HostController.test', 'HostController.test.managers',
                  'HostController.test.infrastructure', 'HostController.logic', 'HostController.crwaler',
                  'HostController.managers','HostController.managers.smart_plug', 'HostController.debugging', 'HostController.miscellaneus',
                  'HostController.report_handler'],
        package_dir={'HostController': 'src/HostController',
                     'HostController.managers': 'src/HostController/managers',
                     'HostController.admin':'src/HostController/admin'},
        package_data={'HostController': ['controller.conf', 'ssdeep.exe', 'boot-ipxe.txt'],
                      'HostController.admin': ['static/*','static/css/*','static/fonts/*','static/js/*']},
        entry_points={'console_scripts':['host_controller_agent=HostController.logic.app:main',
                                         'host_controller_admin=HostController.admin.server:main']},
        url='',
        install_requires=[
                        "enum",
                        "jsonschema",
                        #"zsi", # Omitted for linux compatibility
                        #"vboxapi",
                        #"pypiwin32", # Omitted for linux compatibility
                        "openstacksdk",
                        "sqlalchemy",
                        "requests==2.10",
                        "flask",
                        "lxml",
                        "requests_ftp",
                        "psycopg2",
                        "wmi",
                        "pygments",
                        "ipaddress"],
        license='',
        author='Alberto Geniola',
        author_email='albertogeniola@gmail.com',
        description=''
)
