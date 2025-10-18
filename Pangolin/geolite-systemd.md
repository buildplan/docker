## Service

`geolite2-update.servivice`

```
[Unit]
Description=GeoLite2 Database Update
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
# Update ExecStart path to where you install the script
ExecStart=/usr/local/bin/geolite2-update.sh
# Optionally run as a specific user (change as needed)
User=root
Group=root
# Limit privileges
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true
TimeoutStartSec=600
```

## Timer

`geolite2-update.timer`

```
[Unit]
Description=Run GeoLite2 Database Update on schedule (Wed & Sat 06:30 UTC)

[Timer]
# Run on Wed and Sat at 06:30
OnCalendar=Wed *-*-* 06:30:00
OnCalendar=Sat *-*-* 06:30:00
Persistent=true
Unit=geolite2-update.service

[Install]
WantedBy=timers.target
```
