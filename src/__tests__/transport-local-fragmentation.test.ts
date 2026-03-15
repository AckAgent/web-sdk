/**
 * Tests for BLE fragmentation and reassembly utilities used by local transport.
 */

import { describe, it, expect } from "vitest";
import {
  BLEFragmenter,
  BLEReassembler,
  decodeFragment,
  encodeFragment,
  FragmentFlags,
  MAX_PAYLOAD_SIZE,
  MAX_REASSEMBLY_BYTES,
} from "../transport/local/fragmentation.js";

describe("BLE fragmentation", () => {
  it("encodes and decodes fragments", () => {
    const fragment = {
      flags: FragmentFlags.FIRST | FragmentFlags.LAST,
      sequence: 7,
      payload: new Uint8Array([1, 2, 3, 4]),
    };

    const encoded = encodeFragment(fragment);
    const decoded = decodeFragment(encoded);

    expect(decoded).not.toBeNull();
    expect(decoded?.flags).toBe(fragment.flags);
    expect(decoded?.sequence).toBe(fragment.sequence);
    expect(Array.from(decoded?.payload ?? [])).toEqual(
      Array.from(fragment.payload),
    );
  });

  it("fragments and reassembles a single small payload", () => {
    const payload = new Uint8Array([10, 20, 30]);

    const fragmenter = new BLEFragmenter();
    const fragments = fragmenter.fragment(payload);

    expect(fragments).toHaveLength(1);
    expect(fragments[0].flags).toBe(FragmentFlags.FIRST | FragmentFlags.LAST);

    const reassembler = new BLEReassembler();
    const result = reassembler.addFragment(fragments[0]);

    expect(result).toBeDefined();
    expect(Array.from(result ?? [])).toEqual(Array.from(payload));
  });

  it("fragments and reassembles a multi-fragment payload", () => {
    const payload = new Uint8Array(MAX_PAYLOAD_SIZE * 2 + 25);
    for (let i = 0; i < payload.length; i += 1) {
      payload[i] = i % 256;
    }

    const fragmenter = new BLEFragmenter();
    const fragments = fragmenter.fragment(payload);

    expect(fragments.length).toBeGreaterThan(1);
    expect(fragments[0].flags & FragmentFlags.FIRST).toBe(FragmentFlags.FIRST);
    expect(fragments[fragments.length - 1].flags & FragmentFlags.LAST).toBe(
      FragmentFlags.LAST,
    );

    const reassembler = new BLEReassembler();
    let result: Uint8Array | undefined;
    for (const fragment of fragments) {
      result = reassembler.addFragment(fragment) ?? result;
    }

    expect(result).toBeDefined();
    expect(Array.from(result ?? [])).toEqual(Array.from(payload));
  });

  it("handles empty payloads", () => {
    const fragmenter = new BLEFragmenter();
    const fragments = fragmenter.fragment(new Uint8Array(0));

    expect(fragments).toHaveLength(1);
    expect(fragments[0].flags).toBe(FragmentFlags.FIRST | FragmentFlags.LAST);

    const reassembler = new BLEReassembler();
    const result = reassembler.addFragment(fragments[0]);

    expect(result).toBeDefined();
    expect(result?.length).toBe(0);
  });

  it("resets on out-of-order fragments", () => {
    const payload = new Uint8Array(MAX_PAYLOAD_SIZE + 10);
    for (let i = 0; i < payload.length; i += 1) {
      payload[i] = (i * 3) % 256;
    }

    const fragmenter = new BLEFragmenter();
    const fragments = fragmenter.fragment(payload);

    const reassembler = new BLEReassembler();

    // Send second fragment first (out of order)
    const early = reassembler.addFragment(fragments[1]);
    expect(early).toBeUndefined();
    expect(reassembler.isReassembling).toBe(false);

    // Now send all fragments in order
    let result: Uint8Array | undefined;
    for (const fragment of fragments) {
      result = reassembler.addFragment(fragment) ?? result;
    }

    expect(result).toBeDefined();
    expect(Array.from(result ?? [])).toEqual(Array.from(payload));
  });

  it("rejects reassembly exceeding MAX_REASSEMBLY_BYTES", () => {
    const payloadPerFragment = MAX_PAYLOAD_SIZE;
    const numFragments =
      Math.ceil(MAX_REASSEMBLY_BYTES / payloadPerFragment) + 1;

    const reassembler = new BLEReassembler();

    for (let i = 0; i < numFragments; i++) {
      let flags = 0;
      if (i === 0) flags |= FragmentFlags.FIRST;
      if (i === numFragments - 1) flags |= FragmentFlags.LAST;

      const result = reassembler.addFragment({
        flags,
        sequence: i & 0xff,
        payload: new Uint8Array(payloadPerFragment),
      });

      if (i < numFragments - 1) {
        // Should return undefined while accumulating (or after rejection)
        expect(result).toBeUndefined();
      }
    }

    // Should not have produced a result (rejected due to size)
    expect(reassembler.isReassembling).toBe(false);
  });

  it("recovers after rejecting oversized message", () => {
    const payloadPerFragment = MAX_PAYLOAD_SIZE;
    const numFragments =
      Math.ceil(MAX_REASSEMBLY_BYTES / payloadPerFragment) + 1;

    const reassembler = new BLEReassembler();

    // Send oversized message
    for (let i = 0; i < numFragments; i++) {
      let flags = 0;
      if (i === 0) flags |= FragmentFlags.FIRST;
      if (i === numFragments - 1) flags |= FragmentFlags.LAST;

      reassembler.addFragment({
        flags,
        sequence: i & 0xff,
        payload: new Uint8Array(payloadPerFragment),
      });
    }

    // Should recover and handle normal messages
    const smallPayload = new Uint8Array([1, 2, 3]);
    const fragmenter = new BLEFragmenter();
    const fragments = fragmenter.fragment(smallPayload);

    let result: Uint8Array | undefined;
    for (const fragment of fragments) {
      result = reassembler.addFragment(fragment) ?? result;
    }

    expect(result).toBeDefined();
    expect(Array.from(result ?? [])).toEqual(Array.from(smallPayload));
  });
});
