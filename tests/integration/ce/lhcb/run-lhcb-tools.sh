#!/bin/bash
# Run LHCb's own clients in AlmaLinux 9, against the host's CVMFS.
#
#   ./run-lhcb-tools.sh                  # a shell with the LHCb environment
#   ./run-lhcb-tools.sh 'dirac-login --help'
#
# Needs /cvmfs mounted where this runs (the CVMFS client needs FUSE, which Docker
# Desktop on macOS does not give a container - hence the bind mount).
set -u
cd "$(dirname "$0")"
if [ ! -d /cvmfs/lhcb.cern.ch ]; then
    echo "/cvmfs/lhcb.cern.ch is not mounted here." >&2
    echo "On the VM: it is (net use the VM itself, or mount CVMFS on this host)." >&2
    exit 1
fi
exec docker run --rm -it --platform linux/arm64 \
    -v /cvmfs:/cvmfs:ro \
    -v "${HOME}/.x509up:/work/proxy.pem:ro" \
    -e X509_USER_PROXY=/work/proxy.pem \
    -e BEARER_TOKEN_FILE=/work/token \
    -v "$(pwd)/work:/work" \
    lhcb-tools:latest -c "${1:-source /cvmfs/lhcb.cern.ch/etc/login.sh; bash -i}"
