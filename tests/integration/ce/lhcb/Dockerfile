# An AlmaLinux 9 container that borrows the host's CVMFS, for LHCb's own clients.
#
# The CVMFS tree is *mounted*, not installed: on macOS the CVMFS client runs on the
# host (or VM), where FUSE is available, and a container can only see it through a
# bind mount. So this image carries the userspace, and /cvmfs arrives at run time.
FROM almalinux:9

RUN dnf install -y -q python3.12 python3.12-pip procps which findutils tar \
    && dnf clean all

# LHCb's clients are the ones to use: they know LHCb's DiracX client id, its
# extensions, and its scopes - which is exactly what a generic client cannot guess.
ENV LHCB_ENV=/cvmfs/lhcb.cern.ch/etc/login.sh

WORKDIR /work
ENTRYPOINT ["/bin/bash"]
