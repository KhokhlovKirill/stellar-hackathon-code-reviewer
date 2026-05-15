"""Server-rendered control plane (FastAPI + Jinja2, minimal JS).

Architecture decision docs/08 §5: Jinja2 over a heavy SPA — production
reliability and deploy simplicity. Auth is the same signed token as the API,
carried in an httponly `aegis_session` cookie.
"""

from aegis.web.routes import router

__all__ = ["router"]
