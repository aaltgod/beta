# beta

Simple MITM proxy for AD usage.

## English | [Русский](https://github.com/aaltgod/beta/blob/master/README_RU.md)

## Description

- Redirects traffic to the specified address according to the `config.yaml` configuration;
- Replaces flags in the traffic found by a regular expression and stores them in Redis.

The functionality is graphically represented below:

![alt text](/docs/scheme.svg)

## Startup

- Configure `.env`;
- Configure `config.yaml`. For example, there is service port `5005`, patched service is on address `10.136.179.132`, so the config line should be:

```yml
- { team_host: 10.136.179.132, port: 5005 }
```

- Set up traffic redirection to `beta` from the specified port. For example, if you need to redirect traffic from port `5005` using iptables, you would need to write:

```sh
iptables -t nat -A PREROUTING -p tcp --dport 5005 -j REDIRECT --to-port 29220
```

where `29220` is the default port for `beta`;

- Run 
```sh
docker compose -f docker-compose.yaml up --build -d
```
