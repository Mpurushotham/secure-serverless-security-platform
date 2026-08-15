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
ENTRYPOINT ["python", "-m", "security_posture.exporter"]
