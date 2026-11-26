#!/usr/bin/env python3
#
# Minimal gRPC client for the Holo northbound, used by the
# kernel-leak-bgp acceptance test.
#
# Usage:
#   nb.py commit <socket> <json-file>
#   nb.py get    <socket> <yang-path>
#
# YANG paths use list keys inline: /rib=name=tailscale-v4/routes/route
# The generated gRPC stubs directory must be in $HOLO_GEN.
#
import json
import os
import sys

sys.path.insert(0, os.environ["HOLO_GEN"])

import grpc  # noqa: E402
import holo_pb2  # noqa: E402
import holo_pb2_grpc  # noqa: E402


def stub(socket_path):
    # grpc-python would put the URL-encoded unix path in :authority, which
    # strict HTTP/2 servers reject; pin the authority to a valid value.
    channel = grpc.insecure_channel(
        "unix:" + socket_path,
        options=[("grpc.default_authority", "holo")],
    )
    return holo_pb2_grpc.NorthboundStub(channel)


def parse_path(spec):
    path = holo_pb2.Path()
    for segment in spec.strip("/").split("/"):
        name, has_keys, keys = segment.partition("=")
        elem = path.elem.add(name=name)
        if has_keys:
            for pair in keys.split(","):
                key, _, value = pair.partition("=")
                elem.key[key] = value
    return path


def main():
    command, socket_path, target = sys.argv[1:4]
    client = stub(socket_path)
    if command == "commit":
        with open(target) as file:
            request = holo_pb2.CommitRequest(
                operation=holo_pb2.CommitRequest.MERGE,
                config=holo_pb2.DataTree(
                    encoding=holo_pb2.JSON, data_string=file.read()
                ),
            )
        response = client.Commit(request)
        print(f"committed (transaction {response.transaction_id})")
    elif command == "commit-replace":
        with open(target) as file:
            request = holo_pb2.CommitRequest(
                operation=holo_pb2.CommitRequest.REPLACE,
                config=holo_pb2.DataTree(
                    encoding=holo_pb2.JSON, data_string=file.read()
                ),
            )
        response = client.Commit(request)
        print(f"replaced (transaction {response.transaction_id})")
    elif command == "get":
        request = holo_pb2.GetStateRequest(
            encoding=holo_pb2.JSON, path=parse_path(target)
        )
        response = client.GetState(request)
        print(response.data.data_string)
    elif command == "config":
        request = holo_pb2.GetConfigRequest(
            encoding=holo_pb2.JSON, path=parse_path(target)
        )
        response = client.GetConfig(request)
        print(response.data.data_string)
    else:
        sys.exit(f"unknown command: {command}")


if __name__ == "__main__":
    main()
