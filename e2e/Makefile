.PHONY: run
run: compose-down compose-up

.PHONY: compose-up
compose-up:
	docker compose up --build --abort-on-container-exit

.PHONY: compose-down
compose-down:
	docker compose down
