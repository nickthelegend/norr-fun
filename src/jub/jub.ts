import {
	Base8,
	Fr,
	type Point,
	addPoint,
	mulPointEscalar,
} from "@zk-kit/baby-jubjub";
import { formatPrivKeyForBabyJub, genRandomBabyJubValue } from "maci-crypto";
import { BASE_POINT_ORDER } from "../constants";

/**
 * Implements El-Gamal encryption on BabyJubJub curve
 * @param publicKey BabyJubJub public key
 * @param point Point to encrypt
 * @param random Randomness for the encryption
 * @returns [c1,c2] - returns 2 different points as a ciphertext
 */
export const encryptPoint = (
	publicKey: bigint[],
	point: bigint[],
	random = genRandomBabyJubValue(),
): [Point<bigint>, Point<bigint>] => {
	const c1 = mulPointEscalar(Base8, random);
	const pky = mulPointEscalar(publicKey as Point<bigint>, random);
	const c2 = addPoint(point as Point<bigint>, pky);

	return [c1, c2];
};

/**
 * Implements El-Gamal encryption on scalar message on BabyJubJub curve
 * @param publicKey Public key to encrypt the message
 * @param message  Message to encrypt
 * @param random Randomness for the encryption
 * @returns { cipher: [c1,c2], random: bigint } - returns 2 different points as a ciphertext and the randomness used
 */
export const encryptMessage = (
	publicKey: bigint[],
	message: bigint,
	random = genRandomBabyJubValue(),
): { cipher: [bigint[], bigint[]]; random: bigint } => {
	let encRandom = random;
	if (encRandom >= BASE_POINT_ORDER) {
		encRandom = genRandomBabyJubValue() / 100n;
	}
	const p = mulPointEscalar(Base8, message);

	return {
		cipher: encryptPoint(publicKey, p, encRandom),
		random: encRandom,
	};
};

/**
 * Implements El-Gamal decryption on BabyJubJub curve
 * @param privateKey - Private key to decrypt the point
 * @param c1 - First part of the cipher
 * @param c2 - Second part of the cipher
 * @returns Point - returns the decrypted point
 */
/**
 * ElGamal decryption using an already-formatted BabyJubJub scalar.
 *
 * Prefer this when the scalar came from `keyDerivation.formatDecryptionKey`
 * (the SDK's scheme). `decryptPoint` below applies maci's
 * `formatPrivKeyForBabyJub`, which is a *different* formatting -- feeding it an
 * SDK-formatted scalar would format twice and decrypt to noise, which is
 * exactly the "cannot read my own balance" symptom this migration fixes.
 */
export const decryptPointWithFormattedKey = (
	formattedPrivateKey: bigint,
	c1: bigint[],
	c2: bigint[],
): bigint[] => {
	const c1x = mulPointEscalar(c1 as Point<bigint>, formattedPrivateKey);
	const c1xInverse = [Fr.e(c1x[0] * -1n), c1x[1]];
	return addPoint(c2 as Point<bigint>, c1xInverse as Point<bigint>);
};

/**
 * ElGamal decryption from a raw (maci-scheme) private key.
 *
 * @deprecated for eERC accounts -- the raw key here is formatted with maci's
 * `formatPrivKeyForBabyJub`, which does not agree with `@avalabs/eerc-sdk`.
 * Retained for the legacy test stack, whose `User` uses the same formatting.
 */
export const decryptPoint = (
	privateKey: bigint,
	c1: bigint[],
	c2: bigint[],
): bigint[] =>
	decryptPointWithFormattedKey(formatPrivKeyForBabyJub(privateKey), c1, c2);
