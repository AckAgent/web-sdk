/**
 * Protocol types re-exported from @ackagent/api.
 * Types are accessed via components['schemas']['TypeName'] pattern from the API package.
 */
import type { components } from '@ackagent/api/protocol';

// Payload types
export type WebPayload = components['schemas']['WebPayload'];
export type BasePayload = components['schemas']['BasePayload'];

// Response types
export type WebApprovalResponse = components['schemas']['WebApprovalResponse'];

// Display types
export type GenericDisplaySchema = components['schemas']['GenericDisplaySchema'];
export type DisplayField = components['schemas']['DisplayField'];

// Browser metadata
export type BrowserMetadata = components['schemas']['BrowserMetadata'];

// Common types (dots in schema names require bracket notation)
export type AckAgentCommonTransactionType = components['schemas']['AckAgent.Common.TransactionType'];
export type AckAgentCommonSigningErrorCode = components['schemas']['AckAgent.Common.SigningErrorCode'];
