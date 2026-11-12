#!/bin/bash
# Build the pool, prove it with a real job, then run the client against it.
set -euo pipefail
cd "$(dirname "$0")"

echo "== building and starting the pool"
docker compose up -d --build

echo "== waiting for a slot to advertise"
for _ in $(seq 1 60); do
  if docker compose exec -T submit condor_status 2>/dev/null | grep -q "slot1@execute"; then
    break
  fi
  sleep 3
done
docker compose exec -T submit condor_status | head -4

echo "== a real job through the pool"
docker compose exec -T submit bash -c '
  set -e
  d=/var/lib/condor/runcheck; rm -rf $d; mkdir -p $d; chown condor:condor $d; cd $d
  printf "executable = /bin/echo\narguments = the-pool-works\nshould_transfer_files = YES\nwhen_to_transfer_output = ON_EXIT\noutput = out.txt\nerror = err.txt\nlog = job.log\nqueue\n" > job.sub
  chown condor:condor job.sub
  condor_submit job.sub
  for _ in $(seq 1 30); do sleep 3; condor_q -af JobStatus | grep -q "^$" && break; done
  test "$(cat out.txt)" = "the-pool-works"'

echo "== the client against both daemons"
docker cp probe_pool.py "$(docker compose ps -q submit)":/tmp/probe_pool.py
docker compose exec -T submit python3.12 /tmp/probe_pool.py

echo "== done"
