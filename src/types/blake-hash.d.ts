/**
 * `blake-hash` ships no type declarations. Only the surface the eERC key
 * derivation uses is declared here -- BLAKE-512 over a Buffer -- matching the
 * SDK's own usage (`blake("blake512").update(buf).digest()`).
 *
 * Note this is the original BLAKE, not BLAKE2. `blakejs` is already present in
 * the tree and provides BLAKE2b; the two are not interchangeable, and using the
 * wrong one would silently derive different keys.
 */
declare module "blake-hash" {
    interface BlakeHash {
        update(data: Buffer | Uint8Array | string): BlakeHash;
        digest(): Buffer;
        digest(encoding: "hex"): string;
    }

    function createBlakeHash(algorithm: string): BlakeHash;

    export = createBlakeHash;
}
