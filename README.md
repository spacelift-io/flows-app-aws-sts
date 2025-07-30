# AWS STS OIDC Credentials Service

A Flows app that provides dynamic, auto-refreshing AWS credentials using OpenID Connect (OIDC) federation. This service acts as an OIDC provider and uses AWS STS AssumeRoleWithWebIdentity to generate temporary AWS credentials for other applications and services.

## Overview

This app eliminates the need for static AWS access keys by:

1. **Acting as an OIDC Provider**: Exposes standard OIDC endpoints with self-signed JWT tokens
2. **Federating with AWS IAM**: Uses the OIDC identity to assume AWS IAM roles
3. **Auto-Refreshing Credentials**: Automatically refreshes credentials before expiration
4. **Exposing Credentials as Signals**: Makes AWS credentials available to other Flows apps

## Key Features

- **Zero Static Credentials**: No long-lived AWS access keys needed
- **Automatic Refresh**: Credentials refresh 5 minutes before expiration
- **Configurable Sessions**: Support for custom policies and session duration
- **Standards Compliant**: Full OIDC provider implementation
- **Built-in HTTP Server**: Serves OIDC discovery and JWKS endpoints
- **Signal Integration**: Exposes credentials as consumable signals

## Architecture

```text
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Other Apps    │    │   This App      │    │   AWS STS       │
│                 │    │                 │    │                 │
│ Consume AWS     │◄───┤ • OIDC Provider │────► AssumeRoleWith- │
│ Credentials     │    │ • JWT Signing   │    │ WebIdentity     │
│ via Signals     │    │ • Auto-refresh  │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │  AWS IAM Role   │
                       │ (Web Identity   │
                       │  Trust Policy)  │
                       └─────────────────┘
```

## Quick Start

### 1. Install the App

Deploy this app to your Flows environment. Once installed, note the app's HTTP endpoint URL from the Debug → HTTP section.

### 2. Configure AWS IAM

#### Create Identity Provider

1. Go to **AWS IAM Console → Identity Providers → Add provider**
2. Choose **"OpenID Connect"**
3. **Provider URL**: Your app's endpoint URL (e.g., `https://abc123.flows.com`)
4. **Audience**: The hostname from your endpoint URL (e.g., `abc123.flows.com`)
5. Click **"Get thumbprint"** to auto-populate

#### Create or Configure IAM Role

1. Create a new IAM role or edit existing role
2. Choose **"Web identity"** as trusted entity type
3. Select the identity provider created above
4. Add trust policy conditions:

   ```json
   {
     "StringEquals": {
       "your-hostname:sub": "your-hostname",
       "your-hostname:aud": "your-hostname"
     }
   }
   ```

   Replace `your-hostname` with your actual app hostname.

### 3. Configure the App

Set the following configuration values:

- **Role ARN**: `arn:aws:iam::123456789012:role/MyFlowsRole`
- **Role Session Name**: `FlowsApp-Session`
- **Session Duration**: `3600` (optional, defaults to 1 hour)
- **AWS Region**: `us-east-1` (optional)

### 4. Use the Credentials

The app exposes the following signals that other apps can consume:

- `accessKeyId`: AWS Access Key ID (string)
- `secretAccessKey`: AWS Secret Access Key (sensitive string)
- `sessionToken`: AWS Session Token (sensitive string)
- `expiresAt`: Expiration timestamp in milliseconds (number)

## Configuration Options

| Parameter         | Type     | Required | Description                                         |
| ----------------- | -------- | -------- | --------------------------------------------------- |
| `roleArn`         | string   | ✅       | ARN of the IAM role to assume                       |
| `roleSessionName` | string   | ✅       | Name for the assumed role session                   |
| `durationSeconds` | number   | ❌       | Session duration (300-43200 seconds, default: 3600) |
| `region`          | string   | ❌       | AWS region for STS calls (default: us-east-1)       |
| `policyDocument`  | object   | ❌       | Inline session policy to restrict permissions       |
| `policyArns`      | string[] | ❌       | Managed policy ARNs to attach to session            |

### Example with Session Policy

```json
{
  "roleArn": "arn:aws:iam::123456789012:role/S3ReadOnlyRole",
  "roleSessionName": "S3AccessSession",
  "durationSeconds": 7200,
  "policyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
      }
    ]
  },
  "policyArns": ["arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"]
}
```

## OIDC Endpoints

The app exposes standard OIDC endpoints:

- **Discovery**: `/.well-known/openid-configuration`
- **JWKS**: `/.well-known/jwks`

These endpoints allow AWS and other OIDC-compatible services to verify the JWT tokens generated by this app.

## Security Features

- **RSA-2048 Key Pairs**: Generates secure RSA key pairs for JWT signing
- **Short-lived Tokens**: OIDC tokens expire in 5 minutes
- **Automatic Key Rotation**: Keys are regenerated when configuration changes
- **Secure Storage**: Private keys stored securely in app's key-value store
- **No Static Secrets**: No long-lived AWS credentials stored or transmitted

## Credential Lifecycle

1. **Initial Generation**: On first sync, generates RSA key pair and gets initial credentials
2. **Automatic Refresh**: Scheduled refresh every 10 minutes, refreshes 5 minutes before expiration
3. **Configuration Changes**: Immediately refreshes when configuration changes
4. **Signal Updates**: Credentials exposed via signals for consumption by other apps

## Monitoring and Troubleshooting

### Common Issues

#### Missing required Role ARN

- Ensure the `roleArn` configuration is set correctly

#### AWS STS returned no credentials

- Check that your IAM role trust policy allows the OIDC provider
- Verify the provider URL and audience match your configuration
- Ensure the role has the necessary permissions

#### STS sync failed

- Check AWS region configuration
- Verify network connectivity to AWS STS
- Review CloudTrail logs for detailed error information

### Logs

The app logs key events:

- Credential refresh attempts
- HTTP request handling
- Error conditions with detailed messages

## Use Cases

- **CI/CD Pipelines**: Provide temporary AWS access to build/deploy processes
- **Microservices**: Enable services to access AWS resources without embedding keys
- **Development Environments**: Give developers time-limited AWS access
- **Cross-Account Access**: Assume roles in different AWS accounts securely
- **Compliance**: Meet security requirements for credential rotation and limited lifetime

## Limitations

- **Maximum Session Duration**: AWS limits sessions to 12 hours maximum
- **Role Permissions**: Credentials inherit the permissions of the assumed role
- **Network Dependency**: Requires connectivity to AWS STS for credential refresh
- **Single Role**: Each app instance can only assume one role at a time

## Development

### Prerequisites

- Node.js 20+
- npm

### Available Scripts

```bash
npm run typecheck    # Type checking
npm run format       # Code formatting
npm run bundle       # Create deployment bundle
```

### Testing Your App

1. Run type checking: `npm run typecheck`
2. Format code: `npm run format`
3. Create bundle: `npm run bundle`

## Related Documentation

- [AWS STS AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)
- [AWS IAM OIDC Identity Providers](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)
