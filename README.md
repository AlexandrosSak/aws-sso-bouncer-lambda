# AWS SSO Bouncer Lambda

A serverless access management utility built in Go and deployed to AWS Lambda across multiple regions via Bitbucket Pipelines.

It provides temporary, dynamic IP allowlisting for AWS Security Groups and automatically revokes non-standard access rules at the end of the day to maintain a least-privilege security posture.

## Features

- **Dynamic Access Granting (`bouncer-update`)**: Accepts incoming HTTP requests, extracts client IP from the `X-Forwarded-For` header, and adds a `/32` ingress rule to the target Security Group.
- **Automated Revocation (`bouncer-clear`)**: Runs on a scheduled EventBridge rule to audit and strip away temporary IP permissions, maintaining baseline rules (HTTP/HTTPS/ICMP).
- **Multi-Region Automated Deployment**: Cross-compiles Go binaries for `linux/amd64` and updates Lambda function code concurrently across multiple AWS regions (`eu-west-1`, `eu-west-2`, `us-west-2`).

## Project Structure

```text
.
├── bitbucket-pipelines.yml  # CI/CD pipeline definition
├── go.mod                  # Go module dependencies
├── go.sum                  # Dependency checksums
├── lambda
│   ├── clear
│   │   └── bouncer-clear.go # Scheduled cleanup function
│   └── update
│       └── bouncer-update.go # Dynamic IP access function
├── Makefile                # Build and deployment targets
└── README.md
```

## Environment Variables

Both Lambda functions require the following environment variables:

| Variable | Description |
| :--- | :--- |
| **`BOUNCER_REGION`** | Target AWS Region (defaults to `eu-west-1` if unset) |
| **`BOUNCER_SECURITY_GROUP_ID`** | Target AWS Security Group ID to manage |
| **`ACCOUNT_NAME`** | Display name of the AWS Account for UI responses (`bouncer-update`) |

## Local Development & Build

### Prerequisites

- Go 1.20+
- `zip` utility
- AWS CLI configured with active credentials

### Commands

Compile the Go binaries and build the deployment `.zip` packages:

```bash
make build
```

Deploy updated packages manually to a specific region:

```bash
AWS_REGION=eu-west-1 make deploy
```

## CI/CD Pipeline

The included `bitbucket-pipelines.yml` handles deployment automatically:

- **Build Step**: Uses `golang:1.20.3` container to run `make build`, archiving `.zip` packages as build artifacts.
- **Deploy Step**: Triggered on pushes to `main`. Invokes `make deploy` across `eu-west-1`, `eu-west-2`, and `us-west-2`.
