include .env
export

APP_NAME=beta

.PHONY: run
run: compose-up build
	@sleep 1
	$(info "RUN $(APP_NAME)")

	sudo RUST_LOG=info ./target/release/$(APP_NAME)

.PHONY: build
build:
	$(info "BUILD")
	cargo build --release

.PHONY:
clean: compose-down
	$(info "CLEAN")
	rm -rf bin || true

.PHONY: compose-up
compose-up:
	docker compose -p beta -f ./docker-compose.yaml up --build -d

.PHONY: compose-stop
compose-stop:
	docker compose -p beta -f ./docker-compose.yaml stop

.PHONY: compose-down
compose-down:
	docker compose -p beta -f ./docker-compose.yaml down
