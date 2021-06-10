# charm-easyrsa-operator

## Description

TODO: Describe your charm in a few paragraphs of Markdown

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
