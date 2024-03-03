## How to use nodex-agent with systemd

1. Download a binary of nodex
2. Create a service file for nodex.

Place this file in `/etc/systemd/system/nodex.service`.
And set the path of nodex-agent.

```shell
[Unit]
Description=The NodeX Agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
# if you want to use environment variable, use below line.
# EnvironmentFile=/etc/sysconfig/nodex.env
# path to nodex-agent
ExecStart=/usr/sbin/nodex-agent
PrivateTmp=true
Restart=yes

[Install]
WantedBy=multi-user.target
```

3. reload a systemd

```shell
systemctl daemon-reload
```

4. Check systemd files

```shell
systemctl list-unit-files | grep nodex
```

If the nodex-agent registered, you can show like below.

```shell
root@00cfc06744b3:/# systemctl list-unit-files | grep nodex
nodex.service                          disabled        enabled
```

5. Configure nodex-agent to start automatically

```shell
systemctl enable nodex
```

```shell
root@00cfc06744b3:/# systemctl enable nodex
Created symlink /etc/systemd/system/multi-user.target.wants/nodex.service → /etc/systemd/system/nodex.service.

# If the configuration is successful, the first one will be "enabled".
root@00cfc06744b3:/# systemctl list-unit-files | grep nodex
nodex.service                          enabled         enabled
```
