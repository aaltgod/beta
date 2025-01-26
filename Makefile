include .env
export

APP_NAME=beta

.PHONY: run
run: build
	@sleep 1
	$(info "RUN $(APP_NAME)")

	sudo RUST_LOG=info ./target/release/$(APP_NAME)

.PHONY: build
build:
	$(info "BUILD")
	cargo build --release

.PHONY:
clean: compose-down-local
	$(info "CLEAN")
	rm -rf bin || true

.PHONY: compose-up-local
compose-up-local:
	docker compose -p beta -f ./docker-compose-local.yaml up --build -d

.PHONY: compose-stop-local
compose-stop-local:
	docker compose -p beta -f ./docker-compose-local.yaml stop

.PHONY: compose-down-local
compose-down-local:
	docker compose -p beta -f ./docker-compose-local.yaml down