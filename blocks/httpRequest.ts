import { AppBlock, events } from "@slflows/sdk/v1";
import { SignatureV4 } from "@smithy/signature-v4";
import { Sha256 } from "@aws-crypto/sha256-js";
import { XMLParser } from "fast-xml-parser";

const httpRequest: AppBlock = {
  name: "HTTP Request",
  description:
    "Make an arbitrary HTTP request to AWS APIs using AWS SigV4 signing",
  category: "HTTP",

  inputs: {
    default: {
      name: "HTTP Request",
      description: "Execute HTTP request with AWS SigV4 authentication",
      config: {
        url: {
          name: "URL",
          description: "The complete AWS API URL to make the request to",
          type: "string",
          required: true,
        },
        method: {
          name: "HTTP Method",
          description: "HTTP method to use, defaults to GET",
          type: {
            type: "string",
            enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
          },
          required: false,
        },
        body: {
          name: "Request Body",
          description: "Request body content (for POST, PUT, PATCH methods)",
          type: "string",
          required: false,
        },
        bodyType: {
          name: "Body Type",
          description:
            "Content type for the request body (json, text, binary - binary expects base64-encoded string). Defaults to json",
          type: {
            type: "string",
            enum: ["json", "text", "binary"],
          },
          required: false,
        },
        headers: {
          name: "Additional Headers",
          description:
            'Additional HTTP headers as JSON object (e.g., {"x-custom-header": "value"})',
          type: {
            type: "object",
            additionalProperties: {
              type: "string",
            },
          },
          required: false,
        },
        asJson: {
          name: "Parse Response as JSON",
          description:
            "Parse response to JSON format - converts XML to JSON or parses native JSON responses",
          type: "boolean",
          required: false,
        },
      },
      onEvent: async (input) => {
        const {
          url,
          method = "GET",
          body = "",
          bodyType = "json",
          headers = {},
          asJson = false,
        } = input.event.inputConfig;

        try {
          // Get AWS credentials from app signals
          const accessKeyId = input.app.signals.accessKeyId;
          const secretAccessKey = input.app.signals.secretAccessKey;
          const sessionToken = input.app.signals.sessionToken;

          if (!accessKeyId || !secretAccessKey) {
            throw new Error(
              "AWS credentials not available. Make sure the AWS STS app is properly configured and credentials are generated.",
            );
          }

          // Parse URL to extract service and region
          const parsedUrl = new URL(url);
          const { service, region } = extractServiceAndRegion(
            parsedUrl.hostname,
          );

          if (!service || !region) {
            throw new Error(
              `Cannot extract service and region from hostname: ${parsedUrl.hostname}. Expected format: service.region.amazonaws.com`,
            );
          }

          // Prepare headers
          const requestHeaders: Record<string, string> = {
            host: parsedUrl.hostname,
            ...headers,
          };

          // Set content type based on body type if body is provided
          if (body && !requestHeaders["Content-Type"]) {
            switch (bodyType) {
              case "json":
                requestHeaders["Content-Type"] = "application/x-amz-json-1.1";
                break;
              case "text":
                requestHeaders["Content-Type"] = "text/plain";
                break;
              case "binary":
                requestHeaders["Content-Type"] = "application/octet-stream";
                break;
            }
          }

          // Prepare request body
          let requestBody: BodyInit | undefined;
          if (body && ["POST", "PUT", "PATCH"].includes(method.toUpperCase())) {
            if (bodyType === "json") {
              try {
                // Validate JSON if bodyType is json
                JSON.parse(body);
                requestBody = body;
              } catch (jsonError) {
                throw new Error(
                  `Invalid JSON body: ${jsonError instanceof Error ? jsonError.message : String(jsonError)}`,
                );
              }
            } else if (bodyType === "binary") {
              try {
                // Decode base64 string to binary data
                const binaryData = Uint8Array.from(atob(body), (c) =>
                  c.charCodeAt(0),
                );
                requestBody = binaryData;
              } catch (base64Error) {
                throw new Error(
                  `Invalid base64 binary body: ${base64Error instanceof Error ? base64Error.message : String(base64Error)}`,
                );
              }
            } else {
              requestBody = body;
            }
          }

          // Create signature
          const signer = new SignatureV4({
            credentials: {
              accessKeyId,
              secretAccessKey,
              sessionToken,
            },
            region,
            service,
            sha256: Sha256,
          });

          // Sign the request
          const signedRequest = await signer.sign({
            method: method.toUpperCase(),
            hostname: parsedUrl.hostname,
            path: parsedUrl.pathname + parsedUrl.search,
            protocol: parsedUrl.protocol,
            headers: requestHeaders,
            body: requestBody,
          });

          // Make the HTTP request
          const response = await fetch(url, {
            method: method.toUpperCase(),
            headers: signedRequest.headers,
            body: requestBody,
          });

          // Extract response headers
          const responseHeaders: Record<string, string> = {};
          response.headers.forEach((value, key) => {
            responseHeaders[key] = value;
          });

          // Get response body
          let responseBody: string;
          let parsedJson: any = null;
          try {
            responseBody = await response.text();

            // Parse response to JSON if requested
            if (asJson) {
              const trimmedBody = responseBody.trim();

              if (trimmedBody.startsWith("<")) {
                // Parse XML to JSON
                try {
                  const parser = new XMLParser({
                    ignoreAttributes: true,
                    ignoreDeclaration: true,
                    removeNSPrefix: true,
                    ignorePiTags: true,
                    parseAttributeValue: false,
                    parseTagValue: true,
                    trimValues: true,
                  });
                  parsedJson = parser.parse(responseBody);
                } catch (xmlError) {
                  // If XML parsing fails, just leave parsedJson as null
                  // The original XML will still be available in the body field
                  console.warn("Failed to parse XML response:", xmlError);
                }
              } else if (
                trimmedBody.startsWith("{") ||
                trimmedBody.startsWith("[")
              ) {
                // Parse native JSON response
                try {
                  parsedJson = JSON.parse(responseBody);
                } catch (jsonError) {
                  // If JSON parsing fails, just leave parsedJson as null
                  console.warn("Failed to parse JSON response:", jsonError);
                }
              }
            }
          } catch (bodyError) {
            responseBody = `Failed to read response body: ${bodyError instanceof Error ? bodyError.message : String(bodyError)}`;
          }

          // Emit the response
          const responseData: any = {
            statusCode: response.status,
            statusText: response.statusText,
            headers: responseHeaders,
            body: responseBody,
            url: response.url,
            ok: response.ok,
          };

          // Add parsed JSON if available
          if (parsedJson !== null) {
            responseData.json = parsedJson;
          }

          await events.emit(responseData);
        } catch (error) {
          const errorMessage =
            error instanceof Error ? error.message : String(error);
          throw new Error(`AWS HTTP request failed: ${errorMessage}`);
        }
      },
    },
  },

  outputs: {
    default: {
      name: "HTTP Response",
      description: "Response from the HTTP request",
      type: {
        type: "object",
        properties: {
          statusCode: {
            type: "number",
            description: "HTTP status code",
          },
          statusText: {
            type: "string",
            description: "HTTP status text",
          },
          headers: {
            type: "object",
            description: "Response headers",
            additionalProperties: {
              type: "string",
            },
          },
          body: {
            type: "string",
            description: "Response body as string",
          },
          json: {
            type: "object",
            description:
              "Parsed JSON object (only present when explicitly requested)",
          },
          url: {
            type: "string",
            description: "Final URL after redirects",
          },
          ok: {
            type: "boolean",
            description:
              "Whether the request was successful (status in 200-299 range)",
          },
        },
        required: ["statusCode", "statusText", "headers", "body", "url", "ok"],
      },
    },
  },
};

// Helper function to extract service and region from AWS hostname
function extractServiceAndRegion(hostname: string): {
  service: string | null;
  region: string | null;
} {
  // Handle different AWS hostname patterns:
  // - service.region.amazonaws.com (most common)
  // - service.amazonaws.com (for global services like IAM, S3 in us-east-1)
  // - s3.region.amazonaws.com or s3-region.amazonaws.com (S3 variations)
  // - service-region.amazonaws.com (some services)

  const parts = hostname.split(".");

  if (parts.length < 3 || !hostname.includes("amazonaws.com")) {
    return { service: null, region: null };
  }

  // Standard format: service.region.amazonaws.com
  if (parts.length === 4 && parts[2] === "amazonaws" && parts[3] === "com") {
    const service = parts[0];
    const region = parts[1];

    // Handle special case for global services (no region in hostname)
    if (region === "amazonaws") {
      return { service, region: "us-east-1" }; // Default region for global services
    }

    return { service, region };
  }

  // Handle S3 special cases and service-region format
  const firstPart = parts[0];

  // Check for service-region format (e.g., s3-us-west-2)
  if (firstPart.includes("-") && parts.length >= 3) {
    const dashParts = firstPart.split("-");
    if (dashParts.length >= 2) {
      const service = dashParts[0];
      const region = dashParts.slice(1).join("-");
      return { service, region };
    }
  }

  // Global services format: service.amazonaws.com
  if (parts.length === 3 && parts[1] === "amazonaws" && parts[2] === "com") {
    return { service: parts[0], region: "us-east-1" };
  }

  return { service: null, region: null };
}

export default httpRequest;
