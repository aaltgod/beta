.PHONY: run
run: compose-down compose-up

.PHONY: compose-up
compose-up:
	docker compose up --build --abort-on-container-exit

.PHONY: compose-down
compose-down:
	docker compose down

.PHONY: gen
gen:
	@echo "Generating code..."
	protoc --python_out=client