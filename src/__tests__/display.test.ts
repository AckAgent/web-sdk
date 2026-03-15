import { describe, it, expect } from "vitest";
import { DisplaySchemaBuilder } from "../display.js";
import type { DisplayField } from "../generated/protocol.js";

describe("DisplaySchemaBuilder", () => {
  describe("basic schema", () => {
    it("creates schema with title", () => {
      const schema = new DisplaySchemaBuilder("Test Title").build();
      expect(schema.title).toBe("Test Title");
      expect(schema.fields).toEqual([]);
      expect(schema.subtitle).toBeUndefined();
      expect(schema.icon).toBeUndefined();
    });

    it("sets subtitle", () => {
      const schema = new DisplaySchemaBuilder("Title")
        .subtitle("Test Subtitle")
        .build();
      expect(schema.subtitle).toBe("Test Subtitle");
    });

    it("sets icon", () => {
      const schema = new DisplaySchemaBuilder("Title")
        .icon("star.fill")
        .build();
      expect(schema.icon).toBe("star.fill");
    });
  });

  describe("field types", () => {
    it("adds simple field", () => {
      const schema = new DisplaySchemaBuilder("Title")
        .addField("Name", "John Doe")
        .build();
      expect(schema.fields).toHaveLength(1);
      expect(schema.fields[0]).toEqual({
        label: "Name",
        value: "John Doe",
        monospace: false,
        expandable: false,
        multiline: false,
        sensitive: false,
      });
    });

    it("adds monospace field", () => {
      const schema = new DisplaySchemaBuilder("Title")
        .addMonospaceField("Hash", "abc123")
        .build();
      expect(schema.fields[0]).toEqual({
        label: "Hash",
        value: "abc123",
        monospace: true,
        expandable: false,
        multiline: false,
        sensitive: false,
      });
    });

    it("adds expandable field", () => {
      const schema = new DisplaySchemaBuilder("Title")
        .addExpandableField("Content", "Long content...")
        .build();
      expect(schema.fields[0]).toEqual({
        label: "Content",
        value: "Long content...",
        monospace: false,
        expandable: true,
        multiline: false,
        sensitive: false,
      });
    });

    it("adds multiline field", () => {
      const schema = new DisplaySchemaBuilder("Title")
        .addMultilineField("Description", "Line 1\nLine 2")
        .build();
      expect(schema.fields[0]).toEqual({
        label: "Description",
        value: "Line 1\nLine 2",
        monospace: false,
        expandable: false,
        multiline: true,
        sensitive: false,
      });
    });

    it("adds sensitive field", () => {
      const schema = new DisplaySchemaBuilder("Title")
        .addSensitiveField("Token", "secret-token")
        .build();
      expect(schema.fields[0]).toEqual({
        label: "Token",
        value: "secret-token",
        monospace: false,
        expandable: false,
        multiline: false,
        sensitive: true,
      });
    });

    it("adds code field (monospace + expandable)", () => {
      const schema = new DisplaySchemaBuilder("Title")
        .addCodeField("Command", "npm install")
        .build();
      expect(schema.fields[0]).toEqual({
        label: "Command",
        value: "npm install",
        monospace: true,
        expandable: true,
        multiline: false,
        sensitive: false,
      });
    });

    it("adds custom field with all options", () => {
      const schema = new DisplaySchemaBuilder("Title")
        .addCustomField("Custom", "value", {
          monospace: true,
          expandable: true,
          multiline: true,
          sensitive: true,
        })
        .build();
      expect(schema.fields[0]).toEqual({
        label: "Custom",
        value: "value",
        monospace: true,
        expandable: true,
        multiline: true,
        sensitive: true,
      });
    });
  });

  describe("empty value handling", () => {
    it("skips empty string values", () => {
      const schema = new DisplaySchemaBuilder("Title")
        .addField("Present", "value")
        .addField("Empty", "")
        .addMonospaceField("AlsoEmpty", "")
        .build();
      expect(schema.fields).toHaveLength(1);
      expect(schema.fields[0].label).toBe("Present");
    });
  });

  describe("fluent API", () => {
    it("chains multiple operations", () => {
      const schema = new DisplaySchemaBuilder("Payment Approval")
        .subtitle("$50.00 to merchant")
        .icon("creditcard")
        .addField("Amount", "$50.00")
        .addField("Merchant", "Acme Corp")
        .addMonospaceField("Transaction ID", "txn_123")
        .build();

      expect(schema.title).toBe("Payment Approval");
      expect(schema.subtitle).toBe("$50.00 to merchant");
      expect(schema.icon).toBe("creditcard");
      expect(schema.fields).toHaveLength(3);
    });
  });

  describe("toDisplayObject", () => {
    it("returns object with required fields", () => {
      const obj = new DisplaySchemaBuilder("Title")
        .addField("Key", "Value")
        .toDisplayObject();

      expect(obj.title).toBe("Title");
      expect(obj.fields).toHaveLength(1);
      expect((obj.fields as DisplayField[])[0]).toEqual({
        label: "Key",
        value: "Value",
        monospace: false,
        expandable: false,
        multiline: false,
        sensitive: false,
      });
    });

    it("includes optional fields when set", () => {
      const obj = new DisplaySchemaBuilder("Title")
        .subtitle("Sub")
        .icon("star")
        .toDisplayObject();

      expect(obj.subtitle).toBe("Sub");
      expect(obj.icon).toBe("star");
    });

    it("excludes undefined optional fields", () => {
      const obj = new DisplaySchemaBuilder("Title").toDisplayObject();

      expect("subtitle" in obj).toBe(false);
      expect("icon" in obj).toBe(false);
    });
  });

  describe("immutability", () => {
    it("build returns a copy", () => {
      const builder = new DisplaySchemaBuilder("Title");
      const schema1 = builder.build();
      builder.addField("New", "Field");
      const schema2 = builder.build();

      expect(schema1.fields).toHaveLength(0);
      expect(schema2.fields).toHaveLength(1);
    });
  });
});
