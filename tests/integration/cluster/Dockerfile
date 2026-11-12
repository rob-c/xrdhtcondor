# A single image for every node: AlmaLinux 9, HTCondor from its own repo, and
# the client under test.
FROM almalinux:9

RUN dnf install -y -q \
        https://research.cs.wisc.edu/htcondor/repo/23.0/htcondor-release-current.el9.noarch.rpm \
    && dnf install -y -q condor python3.12 python3.12-pip procps iproute \
    && dnf clean all \
    && python3.12 -m pip -q install --no-cache-dir cryptography

COPY src /pkg/src

ENV PYTHONPATH=/pkg/src
ENV PATH=/usr/sbin:/usr/bin:/sbin:/bin

CMD ["/usr/sbin/condor_master", "-f"]
