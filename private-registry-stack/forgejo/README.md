### Directory Structure

```
forgejo/
├── .env
├── docker-compose.yml
├── forgejo-data
│   ├── git
│   ├── gitea
│   └── ssh
├── forgejo-db
│   ├── PG_VERSION
│   └── DD_STUFF...
└── runner
    └── data
```

### Change runner config at `~/forgejo/runner/data/config.yml`

If there is no `config.yml` execute this:

```
docker compose exec runner forgejo-runner generate-config > ~/forgejo/runner/data/config.yml
```

Then `nano ~/forgejo/runner/data/config.yml` and add the network which is defined in docker compose file. 

```
container:
  network: forgejo_forgejo
```
