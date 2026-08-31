import { expect } from "chai";
import { ethers } from "hardhat";
import blake from "blake-hash";
import { sha256 } from "js-sha256";
import { Base8, mulPointEscalar, subOrder } from "@zk-kit/baby-jubjub";
import {
    deriveDecryptionKey,
    deriveFormattedPrivateKey,
    registerMessage,
} from "../src/utils/keyDerivation";
import { i0 } from "../src/utils/utils";

/**
 * The scripts and the browser must derive the *same* key from the same
 * signature, or an account registered by one cannot read its own encrypted
 * balance in the other.
 *
 * `@avalabs/eerc-sdk` cannot be imported here -- it is ESM with react/wagmi/viem
 * peer dependencies. So its derivation is transcribed below *verbatim* from the
 * shipped bundle and used as a reference oracle: these tests assert our readable
 * implementation agrees with the SDK's actual code, not merely with itself.
 *
 * If the SDK changes its derivation on a future upgrade, the oracle here will
 * still encode the old one -- which is the point. The mismatch surfaces as a
 * failing test rather than as users who silently cannot read their balances.
 */

// ---------------------------------------------------------------------------
// Reference oracle: @avalabs/eerc-sdk@1.0.2, dist/index.js (h0, I, F0, m0).
// Structure and names follow the bundle; only whitespace has been restored.
// ---------------------------------------------------------------------------

const SDK_SUB_ORDER =
    2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const SDK_X =
    115792089237316195423570985008687907853269984665640564039457584007913129639936n;

const sdk_y0 = (x: string) => x.replace(/^0x/, "");
const sdk_U0 = (x: number) => x.toString(16);
const sdk_V0 = (x: number, e = 8) => {
    const a = x % e;
    return a ? ((x - a) / e) * e + e : x;
};
const sdk_W0 = (x: string, e: number, _a: boolean, c = "0") => {
    const f = e - x.length;
    let b = x;
    if (f > 0) b = c.repeat(f) + x;
    return b;
};
const sdk_z0 = (x: string, e: number, a = "0") => sdk_W0(x, e, true, a);
const sdk_$0 = (x: string, e = 8) => sdk_z0(x, sdk_V0(x.length, e), "0");

const sdk_m0 = (x: string, e: number): bigint => {
    const a = sdk_y0(x) + sdk_$0(sdk_U0(e), 2);
    const c = Buffer.from(sdk_y0(a), "hex");
    const f = new Uint8Array(c);
    return BigInt(`0x${sha256.create().update(f).hex()}`);
};

const sdk_F0 = (x: string): string => {
    const e = SDK_SUB_ORDER;
    const a = 1e3;
    const c = SDK_X - (SDK_X % e);
    let f = 0;
    let b = sdk_m0(x, f);
    for (f++; b >= c; ) {
        b = sdk_m0(x, f);
        f++;
        if (f > a) throw new Error("Could not find a valid key");
    }
    return (b % e).toString(16);
};

/** SDK `h0`: signature -> decryption key (hex string). */
const sdk_h0 = (x: string): string => sdk_F0(x.replace(/^0x/, "").slice(0, 64));

/** SDK `I`: decryption key -> formatted scalar. */
const sdk_I = (x: string): bigint => {
    const e = blake("blake512")
        .update(Buffer.from(x, "hex"))
        .digest()
        .slice(0, 32);
    if (e.length < 32) throw new Error("Buffer must be at least 32 bytes long");
    const b = Buffer.from(e);
    b[0] = (b[0] ?? 0) & 248;
    b[31] = ((b[31] ?? 0) & 127) | 64;
    const asBigInt = BigInt(`0x${Buffer.from(b).reverse().toString("hex")}`);
    return (asBigInt >> 3n) % SDK_SUB_ORDER;
};

describe("eERC key derivation (scripts <-> browser)", function () {
    // Each comparison signs a message per signer and rejection-samples a key;
    // that is real work, and the default 40s is tight on a loaded machine.
    this.timeout(180_000);

    it("signs the byte-identical message the SDK signs", () => {
        // Divergent keys would be unsurprising if the signed messages differed;
        // pinning this means future drift is a derivation bug, not a message bug.
        const addr = "0xAbC0000000000000000000000000000000000123";
        expect(registerMessage(addr)).to.equal(
            `eERC\nRegistering user with\n Address:${addr.toLowerCase()}`,
        );
        expect(registerMessage(addr)).to.contain(addr.toLowerCase());
        expect(registerMessage(addr)).to.not.contain(addr); // lower-cased, not raw
    });

    it("derives the same decryption key as the SDK, over many real signatures", async () => {
        const signers = await ethers.getSigners();

        let checked = 0;
        for (const signer of signers.slice(0, 6)) {
            const signature = await signer.signMessage(registerMessage(signer.address));

            expect(deriveDecryptionKey(signature)).to.equal(
                sdk_h0(signature),
                `decryption key diverged for ${signer.address}`,
            );
            checked++;
        }
        expect(checked).to.be.greaterThan(0);
    });

    it("formats to the same curve scalar as the SDK", async () => {
        const signers = await ethers.getSigners();

        for (const signer of signers.slice(0, 6)) {
            const signature = await signer.signMessage(registerMessage(signer.address));
            const ours = deriveFormattedPrivateKey(signature);
            const theirs = sdk_I(sdk_h0(signature));

            expect(ours).to.equal(theirs, `scalar diverged for ${signer.address}`);
            expect(ours).to.be.lessThan(subOrder);
        }
    });

    it("produces the same public key, which is what the Registrar stores", async () => {
        const [signer] = await ethers.getSigners();
        const signature = await signer.signMessage(registerMessage(signer.address));

        const ourPublicKey = mulPointEscalar(
            Base8,
            deriveFormattedPrivateKey(signature),
        ).map((x) => BigInt(x));
        const sdkPublicKey = mulPointEscalar(Base8, sdk_I(sdk_h0(signature))).map((x) =>
            BigInt(x),
        );

        expect(ourPublicKey[0]).to.equal(sdkPublicKey[0]);
        expect(ourPublicKey[1]).to.equal(sdkPublicKey[1]);
    });

    it("is deterministic: the same signature always yields the same key", async () => {
        const [signer] = await ethers.getSigners();
        const signature = await signer.signMessage(registerMessage(signer.address));

        expect(deriveDecryptionKey(signature)).to.equal(deriveDecryptionKey(signature));
        expect(deriveFormattedPrivateKey(signature)).to.equal(
            deriveFormattedPrivateKey(signature),
        );
    });

    it("documents the legacy i0 scheme as genuinely incompatible", async () => {
        // The bug this migration closes, pinned as a test so nobody 'simplifies'
        // the new derivation back into the old one believing they agree.
        const [signer] = await ethers.getSigners();
        const signature = await signer.signMessage(registerMessage(signer.address));

        expect(i0(signature)).to.not.equal(
            deriveFormattedPrivateKey(signature),
            "legacy i0 and the SDK scheme must not be confused for one another",
        );
    });
});
