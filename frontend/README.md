# Aegis Frontend

React + Vite + TypeScript + Tailwind CSS — единственный UI проекта.

## Стек

| Слой | Технология |
|------|------------|
| UI | React 19 |
| Сборка | Vite 6 |
| Язык | TypeScript |
| Стили | Tailwind CSS 4 |
| Роутинг | React Router 7 |
| API | REST `fetch` + JWT в `localStorage` |

## Docker (вместе с бэкендом)

```bash
make docker-up    # из корня репозитория
```

→ **http://localhost:8099**

## Локальная разработка

```bash
make docker-up
cd frontend && npm install && npm run dev
```

→ **http://localhost:5173** (прокси на `localhost:8099`)

## Страницы

| Путь | Назначение |
|------|------------|
| `/login`, `/register` | Аккаунт |
| `/dashboard` | Список проектов |
| `/projects/:id` | Репозитории, сканы, quick connect |
| `/review` | Быстрый review PR без webhook |
| `/scans/:id` | Детали скана |

## Сборка

```bash
npm run build   # → dist/
```
