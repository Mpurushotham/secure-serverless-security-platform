# Distroless, non-root, no shell.
#
# The exporter reads a JSON file and serves text over HTTP. It needs no package
# manager, no shell and no writable filesystem — so it has none, and a remote
# code execution in it has nothing to pivot with.

FROM python:3.11-slim AS build
WORKDIR /build
COPY platform/00-discovery/discovery ./discovery
COPY platform/18-reporting/reporting ./reporting
COPY platform/19-observability/exporters/security_posture ./security_posture

FROM gcr.io/distroless/python3-debian12:nonroot
WORKDIR /app
COPY --from=build /build /app
ENV PYTHONPATH=/app
USER nonroot
EXPOSE 9877

# Exec form with python, because distroless has no shell and no curl — the
# usual `CMD curl -f ...` would silently never run.
#
# It probes /healthz rather than /metrics on purpose: /metrics returns 200 with
# a stale payload if the refresh thread has died, so using it as a liveness
# probe would report healthy for a container serving three-day-old posture data.
# Staleness is surfaced as a metric and alerted on separately; this answers only
# "is the process serving".
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3   CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9877/healthz', timeout=4).status == 200 else 1)"]

ENTRYPOINT ["python", "-m", "security_posture.exporter"]
