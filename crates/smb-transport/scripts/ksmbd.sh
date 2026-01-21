#!/bin/bash
set -euo pipefail

# Soft-RoCE
rdma link add rxe_ens18 type rxe netdev ens18
sleep 0.1

ksmbd.control --debug all
sleep 0.5
ksmbd.control --reload
