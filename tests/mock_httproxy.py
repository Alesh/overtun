import asyncio
import typing as t
import json
import token
from dataclasses import asdict

import h11


class Protocol(asyncio.Protocol):
    def __init__(self, source_transport: asyncio.Transport, host: str, port: int):
        self._transport = None
        self._out_transport = source_transport
        self._h11_ctrl = h11.Connection(our_role=h11.SERVER)
        self._target = (host, port)

    def connection_made(self, transport: asyncio.Transport):
        self._transport = transport

    def data_received(self, data: bytes):
        self._h11_ctrl.receive_data(data)
        try:
            self._h11_process_events()
        except Exception as exc:
            self._send_error(exc)

    def _h11_process_events(self):
        body = b""
        request = None
        seen_end = False
        while not seen_end:
            event = self._h11_ctrl.next_event()
            if isinstance(event, h11.Request):
                request = event
            elif isinstance(event, h11.Data):
                body += event.data
            elif isinstance(event, h11.EndOfMessage):
                seen_end = True
            else:
                if event is h11.PAUSED:
                    self._transport.pause_reading()
                break
        if seen_end:
            if not request:
                raise RuntimeError("The h11.EndOfMessage message was received, but there is no h11.Request message.")
            self._send_success(request, body)

    def _send_success(self, request: h11.Request, body: bytes):
        self._sent_response(
            200,
            "OK",
            dict(
                body=body.decode("utf-8"),
                target=self._target,
                request=dict(
                    (k, [(a.decode(), b.decode()) for a, b in v.raw_items()] if hasattr(v, "raw_items") else v.decode())
                    for k, v in asdict(request).items()
                ),
            ),
        )

    def _send_error(self, exc: Exception):
        self._sent_response(400, "Cannot parse request", dict(target=self._target, exc=str(exc)))

    def _sent_response(self, status_code: int, reason: str, data: dict[str, t.Any]):
        body = json.dumps(data).encode("utf-8")
        headers = [("Content-Length", f"{len(body)}"), ("Content-Type", "application/json; charset=utf-8")]
        if status_code == 400:
            headers.append(("Connection", "close"))
        resp = h11.Response(status_code=status_code, reason=reason, headers=headers)
        self._out_transport.write(self._h11_ctrl.send(resp))
        self._out_transport.write(body)
        self._h11_ctrl.send(h11.EndOfMessage())
        if status_code == 400:
            self._h11_ctrl.send(h11.ConnectionClosed())


class Transport(asyncio.Transport):
    protocol: Protocol

    def __init__(self, extra=None):
        super().__init__(extra)

    def write(self, data):
        self.protocol.data_received(data)

    def close(self):
        self.protocol.connection_lost(None)


async def mock_target_connector(source_transport: Transport, host: str, port: int) -> Transport:
    protocol = Protocol(source_transport, host, port)
    transport = Transport()
    transport.protocol = protocol
    return transport
