import {
  defineApp,
  http,
  kv,
  lifecycle,
  AppInput,
  AppLifecycleCallbackOutput,
  AppOnHTTPRequestInput,
} from "@slflows/sdk/v1";
import { blocks } from "./blocks";
import {
  STSClient,
  AssumeRoleWithWebIdentityCommand,
  AssumeRoleWithWebIdentityCommandInput,
} from "@aws-sdk/client-sts";

// Key value store keys
const KV_KEYS = {
  PRIVATE_KEY: "privateKey",
  PUBLIC_KEY: "publicKey",
  KEY_ID: "keyId",
  EXPIRES_AT: "expiresAt",
  CONFIG_CHECKSUM: "configChecksum",
};

// Constants
const REFRESH_BUFFER_SECONDS = 300; // Refresh 5 minutes before expiration
const DEFAULT_DURATION_SECONDS = 3600; // Default duration (1 hour)
const MAX_DURATION_SECONDS = 43200; // Maximum allowed by AWS (12 hours)
const KEY_SIZE = 2048; // RSA key size
const ALGORITHM = "RS256"; // JWT algorithm

export const app = defineApp({
  name: "AWS STS",

  signals: {
    accessKeyId: {
      name: "AWS Access Key ID",
      description: "AWS access key identifier",
    },
    secretAccessKey: {
      name: "AWS Secret Access Key",
      description: "AWS secret access key",
      sensitive: true,
    },
    sessionToken: {
      name: "AWS Session Token",
      description: "AWS temporary session token",
      sensitive: true,
    },
    expiresAt: {
      name: "Credentials Expiration",
      description: "Unix timestamp (milliseconds) when credentials expire",
    },
  },

  installationInstructions: `To set up this AWS STS app with OIDC federation:

1. **Install and configure the app first**:
   - Install this app and configure the basic settings (Role Session Name, etc.)
   - Leave the "AWS IAM Role ARN" field empty for now
   - The app will show "in_progress" status with message "Now set the role ARN"

2. **Create an AWS IAM Identity Provider**:
   - Go to AWS IAM Console → Identity Providers → Add provider
   - Choose "OpenID Connect"
   - Provider URL: set to <copyable>\`{appEndpointUrl}\`</copyable>
   - Audience: set to <copyable>\`{appEndpointHost}\`</copyable>
   - Thumbprint: Click "Get thumbprint" to auto-populate

3. **Create or update your IAM Role**:
   - Create a new role or edit existing role
   - Choose "Web identity" as trusted entity type
   - Select the identity provider you created above
   - Add conditions (if needed, should be there already): <copyable>\`"StringEquals": {"hostname:sub": "{appEndpointHost}", "hostname:aud": "{appEndpointHost}"}\`</copyable>
   - Attach the desired permissions policies to the role

4. **Complete the app configuration**:
   - Copy the ARN of the IAM role you created
   - Return to this app and paste the Role ARN into the configuration
   - Save the configuration - the app should now succeed and start providing credentials

5. **Use the credentials**:
   - The app exposes AWS credentials as signals that other entities can consume
   - Credentials are automatically refreshed before expiration
   - Use the built-in HTTP Request block to make authenticated AWS API calls`,

  config: {
    roleSessionName: {
      name: "Role Session Name",
      description: "Name for the assumed role session",
      type: "string",
      required: true,
    },
    durationSeconds: {
      name: "Session Duration (seconds)",
      description: `Duration of credentials in seconds (max ${MAX_DURATION_SECONDS}, default ${DEFAULT_DURATION_SECONDS})`,
      type: "number",
      required: false,
      default: DEFAULT_DURATION_SECONDS,
    },
    region: {
      name: "AWS Region",
      description: "AWS region to use for STS calls",
      type: "string",
      required: false,
      default: "us-east-1",
    },
    policyDocument: {
      name: "Session Policy",
      description:
        "Optional IAM policy document to use as an inline session policy",
      type: {},
      required: false,
    },
    policyArns: {
      name: "Managed Policy ARNs",
      description:
        "Optional list of managed policy ARNs to use as session policies",
      type: ["string"],
      required: false,
    },
    roleArn: {
      name: "AWS IAM Role ARN (initially empty)",
      description:
        "ARN of the IAM role to assume. Leave empty initially - you'll fill this after creating the OIDC provider and role in AWS.",
      type: "string",
      required: false,
    },
  },

  async onSync(input: AppInput): Promise<AppLifecycleCallbackOutput> {
    try {
      const config = input.app.config;

      // Validate required config
      if (!config.roleSessionName) {
        return {
          newStatus: "failed",
          customStatusDescription: "Missing required Role Session Name",
        };
      }

      // Check if we need to generate keys
      await ensureKeyPair();

      if (!config.roleArn) {
        return {
          newStatus: "in_progress",
          customStatusDescription: "Now set the role ARN",
        };
      }

      // Check if credentials need refresh
      const needsRefresh = await shouldRefreshCredentials(config);

      if (!needsRefresh) {
        // Credentials still valid, no update needed
        return { newStatus: "ready" };
      }

      // Generate new credentials
      const newCredentials = await generateCredentials(
        config,
        input.app.http.url,
      );

      return {
        newStatus: "ready",
        signalUpdates: {
          accessKeyId: newCredentials.credentials.accessKeyId,
          secretAccessKey: newCredentials.credentials.secretAccessKey,
          sessionToken: newCredentials.credentials.sessionToken,
          expiresAt: newCredentials.expiresAt,
        },
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      console.error("Failed to sync AWS STS app: ", errorMessage);

      return {
        newStatus: "failed",
        customStatusDescription: `STS sync failed: ${errorMessage}`,
      };
    }
  },

  async onDrain(_input: AppInput): Promise<AppLifecycleCallbackOutput> {
    return { newStatus: "drained" };
  },

  http: {
    async onRequest(input: AppOnHTTPRequestInput): Promise<void> {
      const requestPath = input.request.path;

      try {
        if (requestPath === "/.well-known/openid-configuration") {
          // OIDC discovery endpoint
          const response = await handleOidcDiscovery(input.app.http.url);
          await http.respond(input.request.requestId, response);
        } else if (requestPath === "/.well-known/jwks") {
          // JWKS endpoint
          const response = await handleJwks();
          await http.respond(input.request.requestId, response);
        } else {
          await http.respond(input.request.requestId, {
            statusCode: 404,
            body: { error: "Endpoint not found" },
          });
        }
      } catch (error) {
        console.error("HTTP request failed: ", error);
        await http.respond(input.request.requestId, {
          statusCode: 500,
          body: { error: "Internal server error" },
        });
      }
    },
  },

  schedules: {
    "refresh-credentials": {
      description: "Refreshes AWS credentials before they expire",
      customizable: false,
      definition: {
        type: "frequency",
        frequency: {
          interval: 10,
          unit: "minutes",
        },
      },
      async onTrigger() {
        try {
          const { value: expiresAt } = await kv.app.get(KV_KEYS.EXPIRES_AT);

          if (!expiresAt) {
            await lifecycle.sync();
            return;
          }

          const now = Date.now();
          const refreshThreshold = now + REFRESH_BUFFER_SECONDS * 1000;

          if (expiresAt < refreshThreshold) {
            await lifecycle.sync();
          }
        } catch (error) {
          console.error("Error in credential refresh schedule: ", error);
        }
      },
    },
  },

  blocks,
});

// Helper Functions

async function ensureKeyPair(): Promise<void> {
  // Check if all key components exist
  const [{ value: privateKey }, { value: publicKey }, { value: keyId }] =
    await kv.app.getMany([
      KV_KEYS.PRIVATE_KEY,
      KV_KEYS.PUBLIC_KEY,
      KV_KEYS.KEY_ID,
    ]);

  // Only generate keys if any component is missing
  if (!privateKey || !publicKey || !keyId) {
    // Generate RSA key pair
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: KEY_SIZE,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );

    // Export keys
    const privateKeyJwk = await crypto.subtle.exportKey(
      "jwk",
      keyPair.privateKey,
    );
    const publicKeyJwk = await crypto.subtle.exportKey(
      "jwk",
      keyPair.publicKey,
    );

    // Generate stable key ID (use a deterministic approach)
    const newKeyId = crypto.randomUUID();

    // Store keys atomically - all or nothing
    await kv.app.setMany([
      { key: KV_KEYS.PRIVATE_KEY, value: privateKeyJwk },
      { key: KV_KEYS.PUBLIC_KEY, value: publicKeyJwk },
      { key: KV_KEYS.KEY_ID, value: newKeyId },
    ]);
  }
}

async function shouldRefreshCredentials(config: any): Promise<boolean> {
  const [{ value: expiresAt }, { value: previousChecksum }] =
    await kv.app.getMany([KV_KEYS.EXPIRES_AT, KV_KEYS.CONFIG_CHECKSUM]);

  // Check if config changed
  const currentChecksum = await generateChecksum(config);
  const configChanged =
    !previousChecksum || currentChecksum !== previousChecksum;

  // Check if credentials expired or close to expiring
  const now = Date.now();
  const refreshThreshold = now + REFRESH_BUFFER_SECONDS * 1000;
  const needsRefresh = !expiresAt || expiresAt < refreshThreshold;

  // Refresh if config changed or expiring soon
  return configChanged || needsRefresh;
}

async function generateCredentials(config: any, appUrl: string) {
  let oidcToken: string;

  try {
    // Create OIDC token
    oidcToken = await createOidcToken(appUrl);

    // Exchange token for AWS credentials
    const stsClient = new STSClient({ region: config.region });

    const durationSeconds = Math.min(
      config.durationSeconds || DEFAULT_DURATION_SECONDS,
      MAX_DURATION_SECONDS,
    );

    const params: AssumeRoleWithWebIdentityCommandInput = {
      RoleArn: config.roleArn,
      WebIdentityToken: oidcToken,
      RoleSessionName: config.roleSessionName,
      DurationSeconds: durationSeconds,
    };

    // Add optional policy parameters
    if (config.policyDocument) {
      params.Policy = JSON.stringify(config.policyDocument);
    }

    if (
      config.policyArns &&
      Array.isArray(config.policyArns) &&
      config.policyArns.length > 0
    ) {
      params.PolicyArns = config.policyArns.map((arn: string) => ({ arn }));
    }

    const command = new AssumeRoleWithWebIdentityCommand(params);

    const response = await stsClient.send(command);

    if (!response.Credentials) {
      throw new Error("AWS STS returned no credentials");
    }

    const { AccessKeyId, SecretAccessKey, SessionToken, Expiration } =
      response.Credentials;

    if (!AccessKeyId || !SecretAccessKey || !SessionToken) {
      throw new Error("AWS STS returned incomplete credentials");
    }

    const expiresAt =
      Expiration?.getTime() || Date.now() + durationSeconds * 1000;

    const credentials = {
      accessKeyId: AccessKeyId,
      secretAccessKey: SecretAccessKey,
      sessionToken: SessionToken,
    };

    // Store credentials and config checksum
    const configChecksum = await generateChecksum(config);
    await kv.app.setMany([
      { key: KV_KEYS.EXPIRES_AT, value: expiresAt },
      { key: KV_KEYS.CONFIG_CHECKSUM, value: configChecksum },
    ]);

    return { credentials, expiresAt };
  } catch (error) {
    console.error(
      "AWS STS failed: ",
      error instanceof Error ? error.message : String(error),
    );
    throw error;
  }
}

async function createOidcToken(appUrl: string): Promise<string> {
  const { value: privateKeyJwk } = await kv.app.get(KV_KEYS.PRIVATE_KEY);
  const { value: keyId } = await kv.app.get(KV_KEYS.KEY_ID);

  if (!privateKeyJwk || !keyId) {
    throw new Error("Private key or key ID not found");
  }

  // Import private key
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateKeyJwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["sign"],
  );

  // Create JWT header
  const header = {
    alg: ALGORITHM,
    typ: "JWT",
    kid: keyId,
  };

  const appHostname = new URL(appUrl).hostname;

  // Create JWT payload
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: appUrl,
    sub: appHostname,
    aud: appHostname,
    exp: now + 300, // Token expires in 5 minutes
    iat: now,
    nbf: now,
    jti: crypto.randomUUID(),
  };

  // Encode header and payload
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));

  // Create signature
  const signatureData = `${encodedHeader}.${encodedPayload}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(signatureData),
  );

  const encodedSignature = base64UrlEncode(signature);

  return `${signatureData}.${encodedSignature}`;
}

async function handleOidcDiscovery(appUrl: string) {
  const hostname = new URL(appUrl).hostname;
  const discoveryDoc = {
    issuer: hostname,
    jwks_uri: `${appUrl}/.well-known/jwks`,
    response_types_supported: ["id_token"],
    subject_types_supported: ["pairwise", "public"],
    id_token_signing_alg_values_supported: [ALGORITHM],
    claims_supported: ["sub", "aud", "exp", "iat", "iss", "jti", "nbf"],
  };

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: discoveryDoc,
  };
}

async function handleJwks() {
  const { value: publicKeyJwk } = await kv.app.get(KV_KEYS.PUBLIC_KEY);
  const { value: keyId } = await kv.app.get(KV_KEYS.KEY_ID);

  if (!publicKeyJwk || !keyId) {
    throw new Error("Public key or key ID not found");
  }

  // Match the working OIDC app format - only include essential JWK fields
  const jwks = {
    keys: [
      {
        kid: keyId,
        kty: "RSA",
        n: publicKeyJwk.n,
        e: publicKeyJwk.e,
      },
    ],
  };

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: jwks,
  };
}

function base64UrlEncode(data: string | ArrayBuffer): string {
  let base64: string;

  if (typeof data === "string") {
    base64 = btoa(data);
  } else {
    base64 = btoa(String.fromCharCode(...new Uint8Array(data)));
  }

  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function generateChecksum(obj: any): Promise<string> {
  const configString = JSON.stringify(obj);
  const buffer = new TextEncoder().encode(configString);
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);

  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
