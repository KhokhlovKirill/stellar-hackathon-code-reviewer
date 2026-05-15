"""HTTP surface: webhook gateway, health/metrics, admin portal."""

from aegis.api.app import create_app

__all__ = ["create_app"]
