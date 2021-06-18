# charm-easyrsa-operator

## Description

This charm delivers the EasyRSA application to act as a root Certificate Authority (CA) and create certificates for related charms.

## Usage

    charmcraft pack
    juju deploy ./charm-easyrsa-operator.charm --resource easyrsa-image=gslime/easyrsa:latest
      or
    juju refresh charm-easyrsa-operator --path=./charm-easyrsa-operator.charm

    Debug method:
    juju debug-log -m <juju model_name>
    microk8s.kubectl exec -it pod/<charm_name>-0 -n <juju model_name> -c <container_name> -- <cmd to run in the container>

    Container debug (not the container controlled by juju, but a container for better understanding of what's inside it)
    docker run --rm -it -v ~/.easyrsa:/data -e LOCAL_USER_ID=`id -u $USER` gslime/easyrsa /bin/sh

## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate
    pip install -r requirements-dev.txt

## Testing

The Python operator framework includes a very nice harness for testing
operator behaviour without full deployment. Just `run_tests`:

    ./run_tests

## Current status and things TODO

    * "easyrsa init-pki" was executed by adding the layer "_easyrsa_layer".
        ** TODO: when Pebble supports one-shot cmd in container, switch to use that. There's no need to add a layer since we do not have any configuration options in this charm, nor will config_changed happen
        ** HINTS:
            ** "easyrsa init-pki" is executed in directory /data/ in this charm.
    * "backup" action is currently used to store the certificates in the pod. However, store the certificates in the container or add a volume to store can also be considered.
        ** TODO: find out a suitable location to store the certificates
        ** HINTS: if we use the container as a "real" root CA to sign certificate requests etc, then we should probably not store the certs in the container coz that's not what a CA should do. If we use the pod to store the certs, Pebble should provide a better way to handle files (like pull_dirs, etc). If we attach a volume to the container, we should handle this with a "relation"?
            ** container.list_files returns a pebble.FileInfo subject. If there're directories inside directories, Pebble should provide method like "scp -r"
    * provides "tls-certificates" relation (not fully functional)
