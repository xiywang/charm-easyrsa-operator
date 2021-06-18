#!/usr/bin/env python3
# Copyright 2021 ziyiwang
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

import getpass
import grp
import logging
import os
import pwd
import shutil
import socket
import subprocess
import tarfile

import ops.pebble as pebble

from datetime import datetime

from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, Container, ModelError
from ops.pebble import APIError, ChangeError, ConnectionError, Layer, ServiceStatus

logger = logging.getLogger(__name__)

PKI_BACKUP = '/usr/local/share/easyrsa_backup'
charm_directory = os.getcwd()
easyrsa_directory = "/usr/share/easy-rsa/"
pki_directory_cont = "/data/"
WORKLOAD_CONTAINER = "easyrsa"


def _ensure_backup_dir_exists():
    """Ensure that backup directory exists with proper ownership"""
    try:
        os.mkdir(PKI_BACKUP, mode=0o700)
    except FileExistsError:
        pass

    if not os.path.isdir(PKI_BACKUP):
        logger.error("Backup destination '{}' is not a directory".format(PKI_BACKUP))
        raise RuntimeError('Backup destination is not a directory.')

def _ensure_pki_dir_is_clean():
    """Ensure the pki/ directory exists and clean to store certs copied from container"""
    pki_dir = os.path.join(PKI_BACKUP, "pki")
    if os.path.isdir(pki_dir):
        os.rmdir(pki_dir)
        os.mkdir(pki_dir, mode=0o700)

def configure_copy_extensions(self):
    '''Update the EasyRSA configuration with the capacity to copy the exensions
    through to the resulting certificates. '''
    # Create an absolute path to the file which will not be impacted by cwd.
    openssl_file = os.path.join(easyrsa_directory, 'openssl-easyrsa.cnf')
    # Update EasyRSA configuration with the capacity to copy CSR Requested
    # Extensions through to the resulting certificate. This can be tricky,
    # and the implications are not fully clear on this.
    container = self.unit.get_container(WORKLOAD_CONTAINER)
    conf = container.pull(openssl_file).read()
    with open(".tmp_conf_file", 'w') as f:
        f.write(conf)
    with open(".tmp_conf_file", 'r') as f:
        conf = f.readlines()
    if 'copy_extensions = copy\n' not in conf:
        for idx, line in enumerate(conf):
            if '[ CA_default ]' in line:
                # Insert a new line with the copy_extensions key set to copy.
                conf.insert(idx + 1, "copy_extensions = copy\n")
        with open(".tmp_conf_file", 'w+') as f:
            f.writelines(conf)
    with open(".tmp_conf_file", 'r') as f:
        conf = f.read()
    container.push(openssl_file, conf)

def configure_client_authorization(self):
    '''easyrsa has a default OpenSSL configuration that does not support
    client authentication. Append "clientAuth" to the server ssl certificate
    configuration. This is not default, to enable this in your charm set the
    reactive state 'tls.client.authorization.required'.
    '''
    # Use an absolute path so current directory does not affect the result.
    openssl_config = os.path.join(easyrsa_directory, 'x509-types/server')
    logging.debug('Updating {0}'.format(openssl_config))

    # Read the X509 server extension file in.
    container = self.unit.get_container(WORKLOAD_CONTAINER)
    conf = container.pull(openssl_config).read()
    with open(".tmp_conf_file", "w") as f:
        f.write(conf)
    with open(".tmp_conf_file", "r") as f:
        server_extensions = f.readlines()

    client_server = []
    for line in server_extensions:
        # Replace the extendedKeyUsage with clientAuth and serverAuth.
        if 'extendedKeyUsage' in line:
            line = line.replace('extendedKeyUsage = serverAuth',
                                'extendedKeyUsage = clientAuth, serverAuth')
        client_server.append(line)

    # Write the configuration file back out.
    with open(".tmp_conf_file", "w+") as f:
        f.writelines(client_server)
    with open(".tmp_conf_file", "r") as f:
        client_server = f.read()
    container.push(openssl_config, client_server)

def install_ca(relation_data, certificate_authority):
    """Install a certificiate authority on the system"""
    name = relation_data["unit_name"]
    ca_file = '/usr/local/share/ca-certificates/{0}.crt'.format(name)
    logging.info('Writing CA to container {0} at {1}'.format(name, ca_file))
    # Write the contents of certificate authority to the file.
    container.push(ca_file, certificate_authority)

class CharmEasyrsaOperatorCharm(CharmBase):
    """Charm the service."""

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

        # actions
        self.framework.observe(self.on.backup_action, self._on_backup_action)
        self.framework.observe(self.on.list_backups_action, self._on_list_backups_action)

        # relations
        self.framework.observe(self.on.tls_certificates_relation_joined, self._tls_certificates_relation_changed)

    def _easyrsa_layer(self):
        """Returns Pebble configuration layer for easyrsa."""
        layer = {
            "summary": "easyrsa layer",
            "description": "pebble config layer for easyrsa",
            "services": {
                "easyrsa": {
                    "override": "replace",
                    "command": "/usr/bin/easyrsa --batch init-pki",
                    "startup": "disabled",
                }
            }
        }
        return layer

    def _on_config_changed(self, event):
        """Handle the pebble_ready for the easyrsa container."""
        container = self.unit.get_container(WORKLOAD_CONTAINER)
        #try:
        #    plan = container.get_plan().to_dict()
        #except (APIError, ConnectionError) as error:
        #    logging.debug("Pebble API is not ready. Error: {error}")
        #    event.defer()
        #    return

        logging.info("+++ Configuring OpenSSL to copy extensions.")
        configure_copy_extensions(self)
        logging.info("+++ Configuring X509 server extensions with clientAuth.")
        configure_client_authorization(self)

        layer = self._easyrsa_layer()
        try:
            container.add_layer("easyrsa", layer, combine=True)
        except(APIError, ConnectionError) as error:
            logging.debug("Pebble API is not ready. Error: {error}")
            event.defer()
            return
        try:
            container.start("easyrsa")
        except ChangeError:
            pass

        # generate a new CA
        self._create_certification_authority(self)

        self.unit.status = ActiveStatus("Pod and container are ready")

    def _easyrsa_ca_layer(self):
        """Returns Pebble configuration layer for easyrsa."""
        cmd = []
        cmd += "/usr/bin/easyrsa --batch \"--req-cn={"
        cmd += self.get_service_ip()
        cmd += "}\" build-ca nopass"

        layer = {
            "summary": "easyrsa_ca layer",
            "description": "pebble config layer for easyrsa_ca",
            "services": {
                "easyrsa_ca": {
                    "override": "replace",
                    "command": " ".join(cmd),
                    "startup": "disabled",
                }
            }
        }
        return layer

    def _create_certification_authority(self):
        """Create CA"""
        # if leadership data have been set, do not create CA
        # install_ca in relation unit instead

        logging.info("+++ Creating a new CA.")
        container = self.unit.get_container(WORKLOAD_CONTAINER)
        layer = self._easyrsa_ca_layer()
        try:
            container.add_layer("easyrsa_ca", layer, combine=True)
        except(APIError, ConnectionError) as error:
            logging.debug("Pebble API is not ready. Error: {error}")
            event.defer()
            return
        try:
            container.start("easyrsa_ca")
        except ChangeError:
            pass

        ca_file = 'pki/ca.crt'
        key_file = 'pki/private/ca.key'
        serial_file = 'pki/serial'

        # read the ca/key/serial files to leadership data

        # if leadership data have been set, install CA in relation unit
        content = container.pull(os.path.join(pki_directory_cont, ca_file)).read()
        for relation in self.model.relations.get('tls-certificates', []):
            data = relation.data[self.unit]
            data["common_name"] = service_ip
            data["sans"] = f'["{service_ip}"]'
            data["unit_name"] = self.unit.name
            install_ca(data, content)

    def _on_backup_action(self, event):
        """
        Implementation of easyrsa 'backup' action.

        Currently deployed pki is packed into tarball and stored in the
        backups directory.
        """
        _ensure_backup_dir_exists()

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_name = "easyrsa-{}.tar.gz".format(timestamp)
        backup_path = os.path.join(PKI_BACKUP, backup_name)

        container = self.unit.get_container(WORKLOAD_CONTAINER)
        pki_dir_in_container = os.path.join(pki_directory_cont, "pki")
        file_list = container.list_files(pki_dir_in_container)
        logging.info("=== /data/pki files ===\n{}\n=======".format(file_list))
        if file_list:
            message = "Certs to be backuped:"
            _ensure_pki_dir_is_clean()
            for f in file_list:
                logging.info(f)
                info = pebble.FileInfo.from_dict(f)
                logging.info(info)
                message += "\n{}".format(info.path)
                if info.type == "FileType.FILE":
                    cont = container.pull(info.path).read()
                    file_path_in_pod = os.path.join(os.path.join(PKI_BACKUP, "pki"), info.name)
                    logging.info("writing file to {}".format(file_path_in_pod))
                    with open(file_path_in_pod, "w") as fp:
                        fp.write(cont)
                elif info.type == "FileType.DIRECTORY":
                    container.list_files(info.path)

            with tarfile.open(backup_path, mode="w:gz") as pki_tar:
                pki_tar.add(os.path.join(PKI_BACKUP, "pki"), "pki")
        else:
            message = "No certs to backup."

        logging.debug(message)
        event.set_results({"message": "Backup archive created successfully. Use the juju"
                               "scp command to copy it to your local machine."})

    def _on_list_backups_action(self, event):
        """Implementation of easyrsa 'list-backups' action."""
        file_list = []

        try:
            file_list = os.listdir(PKI_BACKUP)
        except FileNotFoundError:
            pass

        if file_list:
            message = "Available backup files:"
            for f in file_list:
                message += "\n{}".format(f)
        else:
            message = "There are no available backup files."

        event.set_results({"message": message})

    def _get_app_fqdn(self, relation):
        try:
            pod_addr = self.model.get_binding(relation).network.bind_address
            addr = socket.getnameinfo((str(pod_addr), 0), socket.NI_NAMEREQD)[0]
            return addr
        except Exception:
            return

    def _tls_certificates_relation_changed(self, event):
        if self.unit.is_leader():
            address = self._get_app_fqdn(event.relation)
            if not address:
                address = self.model.get_binding(event.relation).network.bind_address

            event.relation.data[self.app]['agent-address'] = str(address)

            event.relation.data[self.app]['port_binary'] = \
                str(self.model.config['agent-port-binary'])

            logger.debug("Published relation data: %s", str(event.relation.data))

        service_ip = self.get_service_ip()

        for relation in self.model.relations.get('tls-certificates', []):
            data = relation.data[self.unit]
            data["common_name"] = service_ip
            data["sans"] = f'["{service_ip}"]'
            data["unit_name"] = self.unit.name

        self.update_container()

if __name__ == "__main__":
    main(CharmEasyrsaOperatorCharm)
