## NodeX daemonize usage

Please built binary before wake up docker image.

If you use Apple Silicon MacOS, you should use an aarch64 binary.

```shell
# built docker image for systemd tests
docker compose -f test_resource/compose.yaml --profile systemd build

# wake up containers
docker compose -f test_resource/compose.yaml --profile systemd up -d

docker compose -f test_resource/compose.yaml --profile systemd exec systemd_test bash

# check nodex status
systemctl status nodex

# If you want to check logs, use below commands.
journalctl -u nodex -f
```

This is an example result.

```shell
❯ docker compose -f test_resource/compose.yaml --profile systemd exec systemd_test bash
root@cc4090b385fe:/# arch
aarch64
root@cc4090b385fe:/# systemctl status nodex
● nodex.service - The NodeX Agent
     Loaded: loaded (/etc/systemd/system/nodex.service; enabled; vendor preset: enabled)
     Active: active (running) since Sun 2024-03-03 19:48:16 JST; 13s ago
   Main PID: 44 (nodex-agent)
      Tasks: 9 (limit: 21551)
     Memory: 15.0M
        CPU: 29ms
     CGroup: /system.slice/nodex.service
             └─44 /usr/sbin/nodex-agent

 3月 03 19:48:16 cc4090b385fe systemd[1]: Started The NodeX Agent.
 3月 03 19:48:16 cc4090b385fe nodex-agent[44]: 2024-03-03T10:48:16.817251220+00:00 [INFO] - nodex_>
 3月 03 19:48:16 cc4090b385fe nodex-agent[44]: 2024-03-03T10:48:16.818322678+00:00 [INFO] - actix_>
 3月 03 19:48:16 cc4090b385fe nodex-agent[44]: 2024-03-03T10:48:16.818392095+00:00 [INFO] - nodex_>
 3月 03 19:48:16 cc4090b385fe nodex-agent[44]: 2024-03-03T10:48:16.818429761+00:00 [INFO] - actix_>
 3月 03 19:48:16 cc4090b385fe nodex-agent[44]: 2024-03-03T10:48:16.818476720+00:00 [INFO] - nodex_

# check logs of nodex
root@cc4090b385fe:/# journalctl -u nodex -f
 3月 03 19:48:16 cc4090b385fe systemd[1]: Started The NodeX Agent.
 3月 03 19:48:16 cc4090b385fe nodex-agent[44]: 2024-03-03T10:48:16.817251220+00:00 [INFO] - nodex_agent - subscribed: nodex/did:nodex:test:EiCW6eklabBIrkTMHFpBln7574xmZlbMakWSCNtBWcunDg - src/main.rs:165
 3月 03 19:48:16 cc4090b385fe nodex-agent[44]: 2024-03-03T10:48:16.818322678+00:00 [INFO] - actix_server::builder - starting 1 workers - /cargo/registry/src/index.crates.io-6f17d22bba15001f/actix-server-2.3.0/src/builder.rs:240
 3月 03 19:48:16 cc4090b385fe nodex-agent[44]: 2024-03-03T10:48:16.818392095+00:00 [INFO] - nodex_agent::controllers::public::nodex_receive - Polling task is started - src/controllers/public/nodex_receive.rs:99
 3月 03 19:48:16 cc4090b385fe nodex-agent[44]: 2024-03-03T10:48:16.818429761+00:00 [INFO] - actix_server::server - Tokio runtime found; starting in existing Tokio runtime - /cargo/registry/src/index.crates.io-6f17d22bba15001f/actix-server-2.3.0/src/server.rs:197
 3月 03 19:48:16 cc4090b385fe nodex-agent[44]: 2024-03-03T10:48:16.818476720+00:00 [INFO] - nodex_agent::handlers::sender - start sender - src/handlers/sender.rs:16
```
