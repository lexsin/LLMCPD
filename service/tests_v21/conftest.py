import socket

import pytest


@pytest.fixture(autouse=True)
def no_network_in_offline_tests(monkeypatch, request):
    if request.node.get_closest_marker("isolated_mysql"):
        return
    def forbidden(*args, **kwargs):
        raise AssertionError("offline test attempted network access")
    original_pair, original_connect = socket.socketpair, socket.socket.connect
    def self_pipe(*args, **kwargs):
        # Windows implements asyncio's private self-pipe through loopback socketpair.
        # Allow only construction of that local pair, not application connect calls.
        with monkeypatch.context() as scoped:
            scoped.setattr(socket.socket, "connect", original_connect)
            return original_pair(*args, **kwargs)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socketpair", self_pipe)
