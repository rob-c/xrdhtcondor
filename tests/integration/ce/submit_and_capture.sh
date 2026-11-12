#!/bin/bash
# Submit to a grid HTCondor-CE with a real client, and capture everything it says.
#
# The proxy and the IGTF trust anchors are mounted from the host, so this needs
# both to exist first (xrd-proxy doctor says whether they do):
#
#   /cvmfs/grid.cern.ch/etc/grid-security/certificates   the CA bundle
#   ~/.x509up                                            the LHCb proxy
#
# Usage: ./submit_and_capture.sh [schedd-host]     (default condorce01.cern.ch)
set -uo pipefail
cd "$(dirname "$0")"

CE="${1:-condorce01.cern.ch}"
CERT_DIR="/cvmfs/grid.cern.ch/etc/grid-security/certificates"
PROXY="${X509_USER_PROXY:-$HOME/.x509up}"
OUT="$(pwd)/capture-$(date +%Y%m%d-%H%M%S)"

for need in "$CERT_DIR" "$PROXY"; do
    if [ ! -e "$need" ]; then
        echo "missing $need - run: sudo bash setup-macos/mount-cvmfs.sh && xrd-proxy init -p12 <bundle>.p12 -voms lhcb"
        exit 1
    fi
done
mkdir -p "$OUT"
# The proxy has to be readable inside the container, and owned by the user that
# runs condor_submit there (uid 1000), so copy it rather than mount it read-only.
cp "$PROXY" "$OUT/proxy.pem"
chmod 600 "$OUT/proxy.pem"

echo "== submitting to $CE as $(basename "$PROXY")"
docker run --rm --platform linux/arm64 \
    -v "$CERT_DIR:/etc/grid-security/certificates:ro" \
    -v "$OUT:/work/out" \
    -e X509_USER_PROXY=/work/out/proxy.pem \
    -e _CONDOR_TOOL_DEBUG="D_SECURITY D_NETWORK D_PROTOCOL D_COMMAND" \
    -e _CONDOR_SEC_CLIENT_AUTHENTICATION_METHODS=GSI \
    -e _CONDOR_GSI_DAEMON_DIRECTORY=/etc/grid-security/certificates \
    htcondor-ce-client:latest -c '
        set -x
        id
        condor_config_val SEC_CLIENT_AUTHENTICATION_METHODS
        cat > /work/job.sub <<JOB
executable = /bin/echo
arguments = hello-from-a-real-client
universe = vanilla
output = out.txt
error = err.txt
log = job.log
queue
JOB
        # tcpdump on the container interface: the handshake in the clear
        (tcpdump -i any -s0 -w /work/out/ce.pcap port 9618 or port 9619 >/work/out/tcpdump.log 2>&1 &)
        sleep 3
        condor_submit -remote "$CE" -pool "$CE":9618 /work/job.sub 2>&1 | tee /work/out/submit.log
        condor_submit -remote "$CE" /work/job.sub 2>&1 | tee -a /work/out/submit2.log
        sleep 4
        pkill -INT tcpdump
        sleep 2
        ls -l /work/out
    '

echo "== captured into $OUT"
ls -l "$OUT" 2>/dev/null
