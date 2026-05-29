# Hybrid Cyber Range Setup

## Components

- OWASP Juice Shop
- DVWA
- Nginx Enterprise Web Server
- MySQL Database

## Docker Compose

The cyber range is orchestrated using Docker Compose.

## Ports

| Service | Port |
|---|---|
| Juice Shop | 3000 |
| DVWA | 8080 |
| Nginx | 8081 |
| MySQL | 3306 |

## Start Environment

```bash
docker compose up -d
```

## Stop Environment

```bash
docker compose down
```

## Verify Running Containers

```bash
docker ps
```