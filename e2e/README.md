# e2e

## E2E scheme

```sh
checker <---> beta <---> service
```

### checker

Asserts generated itself flags with received flags from `beta`.

### beta

Processes traffic.

### service

Validates requests from `beta`.

## Startup

```sh
make run
```
