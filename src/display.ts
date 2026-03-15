/**
 * Display schema builder for creating generic request display metadata.
 * This mirrors the iOS GenericDisplaySchema structure.
 */

import type { GenericDisplaySchema } from "./generated/protocol.js";

/**
 * Builder for creating GenericDisplaySchema with a fluent API.
 *
 * @example
 * ```typescript
 * const schema = new DisplaySchemaBuilder("Approve payment?")
 *   .subtitle("$50.00 to merchant")
 *   .icon("creditcard")
 *   .addField("Amount", "$50.00")
 *   .addMonospaceField("Transaction ID", "txn_abc123")
 *   .build();
 * ```
 */
export class DisplaySchemaBuilder {
  private schema: GenericDisplaySchema;

  /**
   * Create a new display schema builder.
   * @param title - Main title for the approval screen
   */
  constructor(title: string) {
    this.schema = {
      title,
      fields: [],
    };
  }

  /**
   * Set the subtitle (displayed below the title).
   */
  subtitle(subtitle: string): this {
    this.schema.subtitle = subtitle;
    return this;
  }

  /**
   * Set the icon (SF Symbol name for iOS).
   */
  icon(icon: string): this {
    this.schema.icon = icon;
    return this;
  }

  /**
   * Add a simple text field.
   * Empty values are skipped.
   */
  addField(label: string, value: string): this {
    if (!value) return this;
    this.schema.fields.push({
      label,
      value,
      monospace: false,
      expandable: false,
      multiline: false,
      sensitive: false,
    });
    return this;
  }

  /**
   * Add a monospace field (for code, hashes, etc.).
   * Empty values are skipped.
   */
  addMonospaceField(label: string, value: string): this {
    if (!value) return this;
    this.schema.fields.push({
      label,
      value,
      monospace: true,
      expandable: false,
      multiline: false,
      sensitive: false,
    });
    return this;
  }

  /**
   * Add an expandable field for long content.
   * Empty values are skipped.
   */
  addExpandableField(label: string, value: string): this {
    if (!value) return this;
    this.schema.fields.push({
      label,
      value,
      monospace: false,
      expandable: true,
      multiline: false,
      sensitive: false,
    });
    return this;
  }

  /**
   * Add a multiline text field.
   * Empty values are skipped.
   */
  addMultilineField(label: string, value: string): this {
    if (!value) return this;
    this.schema.fields.push({
      label,
      value,
      monospace: false,
      expandable: false,
      multiline: true,
      sensitive: false,
    });
    return this;
  }

  /**
   * Add a sensitive field (partially masked).
   * Empty values are skipped.
   */
  addSensitiveField(label: string, value: string): this {
    if (!value) return this;
    this.schema.fields.push({
      label,
      value,
      monospace: false,
      expandable: false,
      multiline: false,
      sensitive: true,
    });
    return this;
  }

  /**
   * Add a code field (monospace + expandable).
   * Useful for displaying code snippets.
   * Empty values are skipped.
   */
  addCodeField(label: string, value: string): this {
    if (!value) return this;
    this.schema.fields.push({
      label,
      value,
      monospace: true,
      expandable: true,
      multiline: false,
      sensitive: false,
    });
    return this;
  }

  /**
   * Add a field with custom qualifiers.
   * Empty values are skipped.
   */
  addCustomField(
    label: string,
    value: string,
    options: {
      monospace?: boolean;
      expandable?: boolean;
      multiline?: boolean;
      sensitive?: boolean;
    },
  ): this {
    if (!value) return this;
    this.schema.fields.push({
      label,
      value,
      monospace: options.monospace ?? false,
      expandable: options.expandable ?? false,
      multiline: options.multiline ?? false,
      sensitive: options.sensitive ?? false,
    });
    return this;
  }

  /**
   * Build and return the GenericDisplaySchema.
   * Returns a deep copy to ensure immutability.
   */
  build(): GenericDisplaySchema {
    return {
      ...this.schema,
      fields: [...this.schema.fields],
    };
  }

  /**
   * Convert the schema to a display object for embedding in payloads.
   */
  toDisplayObject(): Record<string, unknown> {
    const result: Record<string, unknown> = {
      title: this.schema.title,
      fields: this.schema.fields,
    };
    if (this.schema.subtitle) {
      result.subtitle = this.schema.subtitle;
    }
    if (this.schema.icon) {
      result.icon = this.schema.icon;
    }
    return result;
  }
}
