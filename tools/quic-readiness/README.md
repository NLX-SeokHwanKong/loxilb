# MoQ relay readiness broker

This optional Python 3.11+ broker checks the direct relay endpoint. It
validates the relay's certificate, negotiates MoQ draft 16, and requests
a track in a dedicated readiness namespace. Subscribe success or the
protocol's track-not-found response indicates that the relay handled the
request. The broker reports that verdict before QUIC teardown and keeps
one in-flight check per endpoint until cleanup finishes.

Install the pinned Python dependencies in a virtual environment. Give
the broker and LoxiLB access to the same Unix socket in a private
directory. The socket is created with mode 0600. List each allowed
IPv4 relay endpoint with a separate `--endpoint IP:PORT` argument.
Supply the certificate name shared by these endpoints with
`--server-name`, and the server CA bundle with `--server-ca`.
Use an isolated namespace and track assigned to readiness checks. In
`mtls` mode, use a probe-only identity and pass the active credential
directory with `--credential`. The broker resolves that directory
once per probe to read its `client.pem` and `client.key`.

Start LoxiLB with `--quic-health-events` and
`--quic-readiness-socket`, and configure the monitored UDP endpoint
with the probe request `moq-readiness-v1`. The verified candidate
configuration used a one-second endpoint probe period,
`--quic-readiness-timeout-ms=600`, and a two-failure threshold.
Re-admission requires two consecutive readiness successes. Set
the broker's `--budget` in seconds below the LoxiLB timeout so a
verdict can be returned before the caller's deadline.
