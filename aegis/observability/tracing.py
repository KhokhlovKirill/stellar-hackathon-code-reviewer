"""OpenTelemetry tracing setup."""

from __future__ import annotations

from aegis.observability.logging import get_logger

log = get_logger(__name__)


def setup_tracing() -> None:
    """Configure OpenTelemetry SDK with OTLP exporter."""
    from aegis.config import settings

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME

        resource = Resource.create({SERVICE_NAME: settings.otel_service_name})
        provider = TracerProvider(resource=resource)

        if settings.otel_exporter_otlp_endpoint:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

            exporter = OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))

        trace.set_tracer_provider(provider)
        log.info("tracing.configured", endpoint=settings.otel_exporter_otlp_endpoint)
    except Exception as exc:  # pragma: no cover
        log.warning("tracing.setup_failed", error=str(exc))


def get_tracer(name: str):  # type: ignore[return]
    from opentelemetry import trace
    return trace.get_tracer(name)
