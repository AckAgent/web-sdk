/**
 * BLE message fragmentation for handling MTU limitations.
 * Fragments large messages into chunks that fit within BLE's typical 512-byte MTU.
 */

/** Maximum fragment size (accounting for BLE overhead) */
export const BLE_MAX_FRAGMENT_SIZE = 500;

/** Fragment header size (1 byte flags + 1 byte sequence) */
export const FRAGMENT_HEADER_SIZE = 2;

/** Maximum payload size per fragment */
export const MAX_PAYLOAD_SIZE = BLE_MAX_FRAGMENT_SIZE - FRAGMENT_HEADER_SIZE;

/** Fragment flags */
export const FragmentFlags = {
  FIRST: 0x01,
  LAST: 0x02,
  CONTINUATION: 0x00,
} as const;

/** Maximum reassembled message size (64 KB) */
export const MAX_REASSEMBLY_BYTES = 65_536;

/** A fragment of a BLE message */
export interface BLEFragment {
  flags: number;
  sequence: number;
  payload: Uint8Array;
}

/**
 * Encode a fragment to wire format
 * Wire format: [flags:1][sequence:1][payload:N]
 */
export function encodeFragment(fragment: BLEFragment): Uint8Array {
  const result = new Uint8Array(FRAGMENT_HEADER_SIZE + fragment.payload.length);
  result[0] = fragment.flags;
  result[1] = fragment.sequence;
  result.set(fragment.payload, FRAGMENT_HEADER_SIZE);
  return result;
}

/**
 * Decode a fragment from wire format
 */
export function decodeFragment(data: Uint8Array): BLEFragment | null {
  if (data.length < FRAGMENT_HEADER_SIZE) {
    return null;
  }

  return {
    flags: data[0],
    sequence: data[1],
    payload: data.slice(FRAGMENT_HEADER_SIZE),
  };
}

/**
 * Fragmenter for splitting large messages into BLE-sized chunks
 */
export class BLEFragmenter {
  private readonly maxPayloadSize: number;

  constructor(mtu: number = BLE_MAX_FRAGMENT_SIZE) {
    this.maxPayloadSize = mtu - FRAGMENT_HEADER_SIZE;
  }

  /**
   * Fragment a message into BLE-sized chunks
   */
  fragment(data: Uint8Array): BLEFragment[] {
    if (data.length === 0) {
      // Single empty fragment
      return [
        {
          flags: FragmentFlags.FIRST | FragmentFlags.LAST,
          sequence: 0,
          payload: new Uint8Array(0),
        },
      ];
    }

    const fragments: BLEFragment[] = [];
    let offset = 0;
    let sequence = 0;

    while (offset < data.length) {
      const remaining = data.length - offset;
      const chunkSize = Math.min(remaining, this.maxPayloadSize);
      const chunk = data.slice(offset, offset + chunkSize);

      let flags = 0;
      if (offset === 0) {
        flags |= FragmentFlags.FIRST;
      }
      if (offset + chunkSize >= data.length) {
        flags |= FragmentFlags.LAST;
      }

      fragments.push({
        flags,
        sequence: sequence & 0xff, // Wrap at 255
        payload: chunk,
      });

      offset += chunkSize;
      sequence++;
    }

    return fragments;
  }
}

/**
 * Reassembler for combining fragments back into messages
 */
export class BLEReassembler {
  private fragments: Map<number, Uint8Array> = new Map();
  private expectedNext = 0;
  private started = false;
  private accumulatedBytes = 0;

  /**
   * Add a fragment and return the complete message if done
   * @returns Complete message data if all fragments received, undefined otherwise
   */
  addFragment(fragment: BLEFragment): Uint8Array | undefined {
    // Handle first fragment
    if (fragment.flags & FragmentFlags.FIRST) {
      this.reset();
      this.started = true;
      this.expectedNext = 0;
    }

    if (!this.started) {
      // Haven't seen first fragment yet
      return undefined;
    }

    // Check sequence
    if (fragment.sequence !== this.expectedNext) {
      // Out of order fragment - reset
      this.reset();
      return undefined;
    }

    this.accumulatedBytes += fragment.payload.length;
    if (this.accumulatedBytes > MAX_REASSEMBLY_BYTES) {
      this.reset();
      return undefined;
    }

    this.fragments.set(fragment.sequence, fragment.payload);
    this.expectedNext = (this.expectedNext + 1) & 0xff;

    // Check if complete
    if (fragment.flags & FragmentFlags.LAST) {
      // Calculate total size
      let totalSize = 0;
      for (const payload of this.fragments.values()) {
        totalSize += payload.length;
      }

      // Reassemble in sequence order
      const result = new Uint8Array(totalSize);
      let offset = 0;
      for (let seq = 0; seq < this.expectedNext; seq++) {
        const payload = this.fragments.get(seq);
        if (payload) {
          result.set(payload, offset);
          offset += payload.length;
        }
      }

      this.reset();
      return result;
    }

    return undefined;
  }

  /** Reset the reassembler state */
  reset(): void {
    this.fragments.clear();
    this.expectedNext = 0;
    this.started = false;
    this.accumulatedBytes = 0;
  }

  /** Check if reassembly is in progress */
  get isReassembling(): boolean {
    return this.started;
  }

  /** Get the number of fragments received so far */
  get fragmentCount(): number {
    return this.fragments.size;
  }
}
