#!/usr/bin/env python3
# Copyright 2021 ziyiwang
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service.

Refer to the following post for a quick-start guide that will help you
develop a new k8s charm using the Operator Framework:

    https://discourse.charmhub.io/t/4208
"""

import getpass
import grp
import logging
import os
import pwd
import shutil
import subprocess
import tarfile

from datetime import datetime

from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, Container, ModelError
from ops.pebble import APIError, ConnectionError, Layer, ServiceStatus

logger = logging.getLogger(__name__)

PKI_BACKUP = '/usr/local/share/easyrsa_backup'
charm_directory = os.getcwd()
easyrsa_directory = "/usr/share/easy-rsa/"
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

class CharmEasyrsaOperatorCharm(CharmBase):
    """Charm the service."""

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.backup_action, self._on_backup_action)
        self.framework.observe(self.on.list_backups_action, self._on_list_backups_action)

    def _on_config_changed(self, event):
        """Handle the pebble_ready for the easyrsa container."""
        container = self.unit.get_container(WORKLOAD_CONTAINER)
        try:
            plan = container.get_plan().to_dict()
        except (APIError, ConnectionError) as error:
            logging.debug("Pebble API is not ready. Error: {error}")
            event.defer()
            return

        logging.info('Configuring OpenSSL to copy extensions.')
        configure_copy_extensions(self)
        logging.info('Configuring X509 server extensions with clientAuth.')
        configure_client_authorization(self)

        easyrsa_layer = self._easyrsa_layer()

        pebble_config = Layer(raw=easyrsa_layer)
        try:
            container.add_layer("easyrsa", pebble_config, combine=True)
        except(APIError, ConnectionError) as error:
            logging.debug("Pebble API is not ready. Error: {error}")
            event.defer()
            return

        self.unit.status = ActiveStatus("Pod and container are ready")

    def _easyrsa_layer(self):
        """Returns Pebble configuration layer for easyrsa."""
        cmd = []

        cmd.append("easyrsa --batch init-pki 2>&1")

        pebble_layer = {
            "summary": "easyrsa layer",
            "description": "pebble config layer for easyrsa",
            "services": {
                "easyrsa": {
                    "override": "replace",
                    "summary": "easyrsa",
                    "command": " ".join(cmd),
                    "startup": "enabled",
                }
            },
        }
        return pebble_layer

    def _on_backup_action(self, event):
        """
        Implementation of easyrsa 'backup' action.

        Currently deployed pki is packed into tarball and stored in the
        backups directory.
        """
        _ensure_backup_dir_exists()

        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        backup_name = 'easyrsa-{}.tar.gz'.format(timestamp)
        backup_path = os.path.join(PKI_BACKUP, backup_name)
        with tarfile.open(backup_path, mode='w:gz') as pki_tar:
            pki_tar.add(os.path.join(easyrsa_directory, 'pki'), 'pki')

        logger.debug("Backup created and saved to '{}'".format(backup_path))
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
            message = 'Available backup files:'
            for file in file_list:
                message += '\n{}'.format(file)
        else:
            message = 'There are no available backup files.'

        event.set_results({"message": message})


if __name__ == "__main__":
    main(CharmEasyrsaOperatorCharm)
