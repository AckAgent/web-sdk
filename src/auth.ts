/**
 * Authentication and account management for QR code login.
 *
 * The Web SDK acts as a "requester" - it creates requester sessions that
 * are claimed by "approver" devices (iOS/Android) which sign requests.
 */

import type { StoredAccount } from "./types.js";
import type { SASResult, ApproverKeyInfo } from "./sas.js";
import { computeSASFromApproverKeys } from "./sas.js";
import { NetworkError } from "./errors.js";
import { SessionClient } from "./session-client.js";
import { generateKeyPair, type KeyPair } from "./crypto.js";
import { base64urlEncode } from "./encoding.js";

/** Default timeout for QR code login verification in milliseconds (5 minutes) */
const DEFAULT_LOGIN_TIMEOUT = 300000;

/** Options for creating a requester session */
export interface RequesterSessionOptions {
  /** URL of the relay server */
  relayUrl: string;
  /** Base URL for login links (e.g., 'https://login.ackagent.com') */
  loginUrl: string;
  /** Display name for this requester (shown on approver device) */
  name: string;
  /** Session expiration in seconds (default: 300) */
  expiresIn?: number;
}

/** Result of a successful login */
export interface LoginResult {
  /** The stored account with verified SAS */
  account: StoredAccount;
}

/**
 * Represents an active requester session awaiting SAS verification via QR code.
 * The Web SDK is the requester - it initiates login by creating this session.
 */
export class RequesterSession {
  /** Session ID */
  readonly sessionId: string;
  /** When the session expires */
  readonly expiresAt: Date;
  /** QR code URL for scanning with approver app (iOS/Android) */
  readonly qrCodeUrl: string;
  /**
   * Callback invoked when SAS becomes available (after approver scans QR code).
   * Use this to display SAS emojis/words for user verification.
   */
  onSASAvailable?: (sas: SASResult) => void;

  private readonly client: SessionClient;
  private readonly relayUrl: string;
  private readonly identityKeyPair: KeyPair;

  constructor(
    client: SessionClient,
    relayUrl: string,
    loginUrl: string,
    sessionId: string,
    expiresAt: Date,
    identityKeyPair: KeyPair,
  ) {
    this.client = client;
    this.relayUrl = relayUrl;
    this.sessionId = sessionId;
    this.expiresAt = expiresAt;
    this.identityKeyPair = identityKeyPair;
    this.qrCodeUrl = generateQRCodeUrl(
      loginUrl,
      sessionId,
      identityKeyPair.publicKey,
    );
  }

  /**
   * Wait for the user to verify the SAS on their approver device (iOS/Android).
   *
   * During polling, if onSASAvailable is set, it will be called when the approver
   * device scans the QR code and approver keys become available. The SAS is
   * computed locally from the requester key (in QR code) and approver keys
   * (from server). Display the SAS to the user so they can compare it with
   * their approver device.
   *
   * @param timeoutMs - Maximum time to wait in milliseconds
   * @returns The stored account if verification succeeded
   * @throws NetworkError if verification was rejected
   * @throws TimeoutError if verification timed out
   */
  async waitForVerification(
    timeoutMs = DEFAULT_LOGIN_TIMEOUT,
  ): Promise<StoredAccount> {
    // Handler to compute SAS locally when approver keys become available
    const handleApproverKeysAvailable = this.onSASAvailable
      ? (approverKeys: ApproverKeyInfo[]) => {
          // Compute SAS locally using our public key and approver keys
          const sas = computeSASFromApproverKeys(
            this.identityKeyPair.publicKey,
            approverKeys,
          );
          this.onSASAvailable?.(sas);
        }
      : undefined;

    // Use exponential backoff polling for verification status
    const result = await this.client.pollRequesterSessionVerification(
      this.sessionId,
      timeoutMs,
      undefined, // Use default poll config
      handleApproverKeysAvailable, // Compute SAS when approver keys available
    );

    if (result.status === "rejected") {
      throw new NetworkError("SAS verification rejected by user");
    }

    if (result.status !== "verified") {
      throw new NetworkError(
        `Unexpected requester session status: ${result.status}`,
      );
    }

    // Fetch tokens after successful verification
    const tokens = await this.client.getRequesterSessionTokens(this.sessionId);
    const expiresAt = new Date(Date.now() + tokens.expiresIn * 1000);

    return {
      userId: tokens.userId,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt,
      loggedInAt: new Date(),
      sasVerified: true,
      devices: [],
      identityPrivateKey: this.identityKeyPair.privateKey,
      identityPublicKey: this.identityKeyPair.publicKey,
      relayUrl: this.relayUrl,
    };
  }
}

/**
 * Generate the QR code URL for scanning with approver app (iOS/Android)
 */
export function generateQRCodeUrl(
  loginUrl: string,
  sessionId: string,
  publicKey: Uint8Array,
): string {
  const pkBase64url = base64urlEncode(publicKey);
  return `${loginUrl}/link/login?sid=${sessionId}&pk=${pkBase64url}`;
}

/**
 * Create a requester session for QR code-based authentication.
 *
 * This creates a session and returns a QR code URL for the user to scan with their
 * approver app (iOS/Android). The user scans the QR code, verifies the SAS, and the
 * session becomes verified.
 *
 * @param options - Requester session options
 * @returns A RequesterSession that can be used to wait for verification
 *
 * @example
 * ```typescript
 * const session = await createRequesterSession({
 *   relayUrl: 'https://relay.example.com',
 *   name: 'My Web App',
 * });
 *
 * // Display QR code to user
 * displayQRCode(session.qrCodeUrl);
 * console.log('Scan this QR code with your AckAgent app');
 *
 * // Wait for verification
 * const account = await session.waitForVerification();
 * await storeAccount(account); // Stores in IndexedDB
 * ```
 */
export async function createRequesterSession(
  options: RequesterSessionOptions,
): Promise<RequesterSession> {
  const client = new SessionClient(options.relayUrl);

  // Generate identity key pair for this account (async, non-extractable)
  const identityKeyPair = await generateKeyPair();

  // Create requester session (public endpoint, no auth required)
  const result = await client.createRequesterSession({
    requesterName: options.name,
    requesterPublicKey: identityKeyPair.publicKey,
    expiresIn: options.expiresIn,
  });

  return new RequesterSession(
    client,
    options.relayUrl,
    options.loginUrl,
    result.sessionId,
    result.expiresAt,
    identityKeyPair,
  );
}

/**
 * Perform a complete login flow with QR code verification.
 *
 * This is a convenience function that creates a requester session and waits
 * for verification in one call. Use createRequesterSession() if you need
 * more control over the flow.
 *
 * @param options - Requester session options
 * @param onQRCode - Callback to display QR code to user (must return true to continue)
 * @param timeoutMs - Maximum time to wait for verification
 * @returns The login result with account
 *
 * @example
 * ```typescript
 * const result = await login(
 *   {
 *     relayUrl: 'https://relay.example.com',
 *     name: 'My Web App',
 *   },
 *   (qrCodeUrl, expiresAt) => {
 *     displayQRCode(qrCodeUrl);
 *     return true; // Continue waiting
 *   }
 * );
 *
 * // Store account in IndexedDB
 * await storeAccount(result.account);
 * ```
 */
export async function login(
  options: RequesterSessionOptions,
  onQRCode: (qrCodeUrl: string, expiresAt: Date) => boolean | Promise<boolean>,
  timeoutMs = DEFAULT_LOGIN_TIMEOUT,
): Promise<LoginResult> {
  const session = await createRequesterSession(options);

  // Display QR code to user
  const shouldContinue = await onQRCode(session.qrCodeUrl, session.expiresAt);
  if (!shouldContinue) {
    throw new NetworkError("Login cancelled by user");
  }

  // Wait for verification
  const account = await session.waitForVerification(timeoutMs);

  return {
    account,
  };
}

/**
 * Check if a stored account is still valid (not expired)
 */
export function isAccountValid(account: StoredAccount): boolean {
  return account.sasVerified && account.expiresAt > new Date();
}

/**
 * Check if the account token needs refreshing (expires within 7 days)
 */
export function needsTokenRefresh(account: StoredAccount): boolean {
  const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
  const timeUntilExpiry = account.expiresAt.getTime() - Date.now();
  return timeUntilExpiry < sevenDaysMs;
}

/** Result of a token refresh */
export interface TokenRefreshResult {
  accessToken: string;
  refreshToken?: string;
  expiresAt: Date;
}

/**
 * Refresh tokens using the auth-service token endpoint.
 *
 * @param authServiceUrl - The login service base URL (e.g., https://login.ackagent.com)
 * @param refreshToken - The refresh token to use
 * @param clientId - The OAuth client ID
 * @returns New tokens
 */
export async function refreshTokens(
  authServiceUrl: string,
  refreshToken: string,
  clientId: string,
): Promise<TokenRefreshResult> {
  const tokenUrl = `${authServiceUrl}/token`;

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: clientId,
    }),
  });

  if (!response.ok) {
    throw new NetworkError(`Token refresh failed: ${response.status}`);
  }

  const data = await response.json();

  // Calculate expiry from expires_in (seconds)
  const expiresIn = data.expires_in ?? 3600;
  const expiresAt = new Date(Date.now() + expiresIn * 1000);

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt,
  };
}

/**
 * Update an account with new tokens.
 * Note: You must call storeAccount() after this to persist the changes.
 */
export function updateAccountTokens(
  account: StoredAccount,
  tokens: TokenRefreshResult,
): StoredAccount {
  return {
    ...account,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken ?? account.refreshToken,
    expiresAt: tokens.expiresAt,
  };
}
