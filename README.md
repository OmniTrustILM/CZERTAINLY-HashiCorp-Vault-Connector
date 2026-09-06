# HashiCorp Vault Connector

HashiCorp Vault `Connector` is the implementation of the following `Function Groups` and `Kinds`:

| Function Group       | Kind     |
|----------------------|----------|
| `Authority Provider` | `HVault` |
| `Discovery Provider` | `HVault` |

HashiCorp Vault `Connector` is the implementation of certificate management for HashiCorp Vault PKI secrets engine that is compatible with the v2 client operations interface.

HashiCorp Vault `Connector` allows you to perform the following operations:

`Authority Provider`
- Issue certificate
- Renew certificate
- Revoke certificate
- Identify certificate
- Download CA certificate
- Download CRL

`Discovery Provider`
- Discover certificates

## Database requirements

HashiCorp Vault `Connector` requires the PostgreSQL database version 12+.

## Docker container

HashiCorp Vault `Connector` is provided as a Docker container. Use the `ilm/hashicorp-vault-connector:tagname` image to pull the required image from the repository. It can be configured using the following environment variables:

| Variable            | Description                       | Required                                           | Default value |
|---------------------|-----------------------------------|----------------------------------------------------|---------------|
| `SERVER_PORT`       | Port where the service is exposed | ![](https://img.shields.io/badge/-NO-red.svg)      | `8080`        |
| `DATABASE_HOST`     | Database host                     | ![](https://img.shields.io/badge/-NO-red.svg)      | `localhost`   |
| `DATABASE_PORT`     | Database port                     | ![](https://img.shields.io/badge/-NO-red.svg)      | `5432`        |
| `DATABASE_NAME`     | Database name                     | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`         |
| `DATABASE_USER`     | Database user                     | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`         |
| `DATABASE_PASSWORD` | Database password                 | ![](https://img.shields.io/badge/-YES-success.svg) | `N/A`         |
| `DATABASE_SCHEMA`   | Database schema                   | ![](https://img.shields.io/badge/-NO-red.svg)      | `hvault`      |
| `DATABASE_SSL_MODE` | Database SSL mode                 | ![](https://img.shields.io/badge/-NO-red.svg)      | `require`     |
| `LOG_LEVEL`         | Logging level for the service     | ![](https://img.shields.io/badge/-NO-red.svg)      | `INFO`        |
