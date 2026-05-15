# Frontend

This directory is the frontend boundary for Aegis.

Current contents:

- `templates/` — server-rendered Jinja2 templates used by `backend/aegis/web/routes.py`.

The backend reads templates from `AEGIS_FRONTEND_TEMPLATES`; by default, local backend
runs use `../frontend/templates`, and Docker uses `/app/frontend/templates`.
