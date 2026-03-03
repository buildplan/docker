**`jail.local` with reporting blocks to abuseipdb** 

```ini
[forgejo-sshd]
enabled = true
port = 555,22
filter = forgejo-sshd
backend = systemd
journalmatch = CONTAINER_TAG=forgejo-ssh
maxretry = 2
bantime = 14400
findtime = 7200
chain = DOCKER-USER
action = iptables-multiport[name="forgejo-sshd", port="555,22", protocol="tcp", chain="%(chain)s"]
         %(action_abuseipdb)s[abuseipdb_apikey="abuseipdb_api_key", abuseipdb_category="18,22"]
```

**For my setup logging to `journald` with a custom tag `/etc/fail2ban/filter.d/forgejo-sshd.conf` is like this:**

```ini
[Definition]
failregex = (?i)(?:invalid user|user) \S+ from <HOST>.*
            (?i)Connection (?:closed|reset|reset by) by (?:invalid user \S+ )?<HOST> port \d+.*

ignoreregex = .*?router: completed.*
              .*?healthcheck.*
              .*?PING DATABASE.*
              .*?router: slow.*
              .*?GetRunnerByUUID.*
              .*?Starting Forgejo.*
              .*?ORM engine.*
              .*?Server listening on.*
```
