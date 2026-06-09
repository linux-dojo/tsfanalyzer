.PHONY: dev test build up down

test:
	cd backend && go vet ./... && go test ./...

build:
	cd backend && go build ./...
	cd frontend && npm install && npm run build

up:
	docker compose up --build -d

down:
	docker compose down

dev-api:
	cd backend && go run ./cmd/api

dev-frontend:
	cd frontend && npm run dev
