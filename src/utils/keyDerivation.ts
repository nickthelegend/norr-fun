import blake from "blake-hash";
import { sha256 } from "js-sha256";
import { subOrder } from "@zk-kit/baby-jubjub";

/**
 * eERC key derivation, matching `@avalabs/eerc-sdk` exactly.
 *
 * Both the browser (SDK) and the operator scripts derive a BabyJubJub keypair
 * from the same signature over the same message, but they used to derive it
 * *differently*: the scripts ran `keccak256` over the whole signature (`i0`),
 * while the SDK takes only the first 32 bytes, rejection-samples an iterated
 * `sha256`, then runs `blake512` and shifts right by 3. Same signature, two
 * unrelated keys -- so an account registered by script could not read its own
 * encrypted balance in the browser, and vice versa.
 *
 * The SDK's scheme is canonical here, because the public keys already written
 * on chain by real users are SDK-derived. Migrating the browser instead would
 * invalidate genuine registrations and mean patching a versioned dependency;
 * migrating the scripts is a contained change to tooling we control.
 *
 * Transcribed from `@avalabs/eerc-sdk@1.0.2` (`h0`, `I`, `F0`, `m0` in
 * `dist/index.js`). `test/KeyDerivation.test.ts` checks this implementation
 * against that shipped code as a reference oracle, so drift is caught rather
 * than assumed absent.
 */

/** 2^256 -- the space `m0` samples from, used to compute the rejection bound. */
const SAMPLE_SPACE = 1n << 256n;

/** Largest multiple of `subOrder` that fits in `SAMPLE_SPACE`. */
const REJECTION_THRESHOLD = SAMPLE_SPACE - (SAMPLE_SPACE % subOrder);

/** Give up rather than loop forever; the SDK uses the same bound. */
const MAX_ATTEMPTS = 1000;

const stripHexPrefix = (value: string): string => value.replace(/^0x/, "");

/** Left-pad to an even number of hex characters, so it decodes as whole bytes. */
const padToEvenLength = (value: string): string =>
    value.length % 2 === 0 ? value : `0${value}`;

/**
 * `sha256(keyHex ‖ counter)` as a bigint -- one draw of the rejection sampler.
 * The counter is appended as whole bytes, so draw 0 hashes `…00`, draw 1 `…01`.
 */
function drawAt(keyHex: string, counter: number): bigint {
    const withCounter =
        stripHexPrefix(keyHex) + padToEvenLength(counter.toString(16));
    const bytes = Uint8Array.from(Buffer.from(withCounter, "hex"));
    return BigInt(`0x${sha256.create().update(bytes).hex()}`);
}

/**
 * Derive the decryption key from a registration signature.
 *
 * Only the first 32 bytes of the signature are used, and draws at or above
 * `REJECTION_THRESHOLD` are discarded rather than reduced -- taking `% subOrder`
 * of a raw 256-bit draw would bias the low keys, so the biased tail is rejected
 * and the counter incremented instead.
 *
 * @returns the key as an unprefixed hex string, matching the SDK's shape.
 */
export function deriveDecryptionKey(signature: string): string {
    const first32Bytes = stripHexPrefix(signature).slice(0, 64);

    let counter = 0;
    let draw = drawAt(first32Bytes, counter);
    counter++;

    while (draw >= REJECTION_THRESHOLD) {
        draw = drawAt(first32Bytes, counter);
        counter++;
        if (counter > MAX_ATTEMPTS) {
            throw new Error("Could not find a valid key");
        }
    }

    return (draw % subOrder).toString(16);
}

/**
 * Format a decryption key into the scalar actually used on the curve.
 *
 * `blake512` of the key, clamped the standard Edwards way (clear the low three
 * bits, clear the top bit, set the second-highest), read little-endian, then
 * shifted right by 3 -- the shift undoes the low-bit clearing so the scalar
 * lands in the subgroup.
 */
export function formatDecryptionKey(decryptionKeyHex: string): bigint {
    const digest = blake("blake512")
        .update(Buffer.from(stripHexPrefix(decryptionKeyHex), "hex"))
        .digest()
        .slice(0, 32);

    if (digest.length < 32) {
        throw new Error("Buffer must be at least 32 bytes long");
    }

    const clamped = Buffer.from(digest);
    clamped[0] = (clamped[0] ?? 0) & 248;
    clamped[31] = ((clamped[31] ?? 0) & 127) | 64;

    const littleEndian = BigInt(
        `0x${Buffer.from(clamped).reverse().toString("hex")}`,
    );

    return (littleEndian >> 3n) % subOrder;
}

/**
 * Signature -> the scalar used to build the public key and registration hash.
 * This is the value that must agree with the browser for an account to read
 * its own balance in both places.
 */
export function deriveFormattedPrivateKey(signature: string): bigint {
    return formatDecryptionKey(deriveDecryptionKey(signature));
}

/** The exact message both sides sign, from the SDK's `x0.REGISTER`. */
export const registerMessage = (address: string): string =>
    `eERC\nRegistering user with\n Address:${address.toLowerCase()}`;
