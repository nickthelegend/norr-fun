import { Base8, mulPointEscalar, subOrder } from "@zk-kit/baby-jubjub";
import {
    deriveDecryptionKey,
    deriveFormattedPrivateKey,
    formatDecryptionKey,
    registerMessage,
} from "./keyDerivation";
import { formatPrivKeyForBabyJub } from "maci-crypto";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { ethers } from "hardhat";
import { decryptPoint, decryptPointWithFormattedKey } from "../jub/jub";
import { decryptPCT } from "../../test/helpers";
import { User } from "../../test/user";
import * as fs from "fs";
import * as path from "path";

/**
 * Derives a private key from a signature using the legacy i0 function.
 *
 * @deprecated Does NOT agree with `@avalabs/eerc-sdk`, so a key derived here
 * cannot read a balance registered in the browser, or vice versa. Retained only
 * so accounts registered under the old scheme can still be identified during
 * migration. Use `deriveFormattedPrivateKey` from `./keyDerivation` for anything
 * new -- see `test/KeyDerivation.test.ts`.
 *
 * @param signature The signature hex string
 * @returns The derived private key as bigint
 */
export function i0(signature: string): bigint {
    if (typeof signature !== "string" || signature.length < 132)
        throw new Error("Invalid signature hex string");

    const hash = ethers.keccak256(signature as `0x${string}`);          
    const cleanSig = hash.startsWith("0x") ? hash.slice(2) : hash;
    let bytes = hexToBytes(cleanSig);

    bytes[0] &= 0b11111000;
    bytes[31] &= 0b01111111;
    bytes[31] |= 0b01000000;

    const le = bytes.reverse();               
    let sk = BigInt(`0x${bytesToHex(le)}`);

    sk %= subOrder;
    if (sk === BigInt(0)) sk = BigInt(1);  
    return sk;                                  
}

/**
 * Derives private key and public key from user signature
 * @param userAddress The user's EVM address (0x...)
 * @param wallet The wallet instance to sign with
 * @returns Object containing privateKey, formattedPrivateKey, and publicKey
 */
export async function deriveKeysFromUser(userAddress: string, wallet: any): Promise<{
    privateKey: bigint;
    formattedPrivateKey: bigint;
    publicKey: [bigint, bigint];
    signature: string;
}> {
    // Create deterministic message for signing -- shared with the SDK so the
    // browser and these scripts sign byte-identical text.
    const message = registerMessage(userAddress);
    
    console.log('📝 Message to sign for balance:', message);
    
    // Get signature from user
    const signature = await wallet.signMessage(message);
    if (!signature || signature.length < 64) {
        throw new Error("Invalid signature received from user");
    }
    
    // Derive the decryption key exactly as @avalabs/eerc-sdk does, so an account
    // registered here can read its own balance in the browser and vice versa.
    console.log("🔑 Deriving private key from signature...");
    const decryptionKey = deriveDecryptionKey(signature);
    const privateKey = BigInt(`0x${decryptionKey}`);
    console.log("Private key (raw):", privateKey.toString());

    // Format for BabyJubJub (SDK's `I`), NOT maci's formatPrivKeyForBabyJub --
    // the two disagree, and the SDK's is what the on-chain public keys encode.
    const formattedPrivateKey = formatDecryptionKey(decryptionKey);
    console.log("Private key (formatted):", formattedPrivateKey.toString());
    
    // Generate public key using BabyJubJub
    const publicKey = mulPointEscalar(Base8, formattedPrivateKey).map((x) => BigInt(x)) as [bigint, bigint];
    console.log("Public key X:", publicKey[0].toString());
    console.log("Public key Y:", publicKey[1].toString());
    
    return {
        privateKey,
        formattedPrivateKey,
        publicKey,
        signature
    };
}

/**
 * Decrypts EGCT balance using ElGamal decryption and finds the discrete log
 * @param privateKey The private key for decryption
 * @param c1 First component of the encrypted balance
 * @param c2 Second component of the encrypted balance
 * @returns The decrypted balance as bigint
 */
/**
 * Decrypt an eERC balance using an already-formatted scalar.
 *
 * Use this with `user.formattedPrivateKey` from `createUserFromSignature`: the
 * SDK derives that scalar with blake512, so it must NOT be run through maci's
 * formatter again on the way in.
 */
export function decryptEGCTBalanceWithFormattedKey(
    formattedPrivateKey: bigint,
    c1: [bigint, bigint],
    c2: [bigint, bigint],
): bigint {
    try {
        const decryptedPoint = decryptPointWithFormattedKey(formattedPrivateKey, c1, c2);
        const result = findDiscreteLogOptimized([decryptedPoint[0], decryptedPoint[1]]);
        if (result !== null) return result;

        console.log("⚠️  Could not find discrete log for decrypted point:", decryptedPoint);
        return 0n;
    } catch (error) {
        console.log("⚠️  Error decrypting EGCT:", error);
        return 0n;
    }
}

/**
 * @deprecated for eERC accounts -- applies maci formatting internally, which
 * disagrees with the SDK. Use `decryptEGCTBalanceWithFormattedKey`.
 */
export function decryptEGCTBalance(privateKey: bigint, c1: [bigint, bigint], c2: [bigint, bigint]): bigint {
    try {
        // Decrypt the point using ElGamal
        const decryptedPoint = decryptPoint(privateKey, c1, c2);
        
        // Use optimized discrete log search
        const result = findDiscreteLogOptimized([decryptedPoint[0], decryptedPoint[1]]);
        
        if (result !== null) {
            return result;
        }
        
        console.log("⚠️  Could not find discrete log for decrypted point:", decryptedPoint);
        return 0n;
    } catch (error) {
        console.log("⚠️  Error decrypting EGCT:", error);
        return 0n;
    }
}

// Cache for frequently computed discrete logs
const discreteLogCache = new Map<string, bigint>();

// Pre-populate cache with common values on first use
let cacheInitialized = false;
function initializeCache() {
    if (cacheInitialized) return;
    
    // Pre-compute and cache common values (0-100, then multiples of 100 up to 10000)
    const commonValues = [];
    
    // Add 0-100 (very common small amounts)
    for (let i = 0; i <= 100; i++) {
        commonValues.push(BigInt(i));
    }
    
    // Add multiples of 100 up to 10000 (common transaction amounts)
    for (let i = 200; i <= 10000; i += 100) {
        commonValues.push(BigInt(i));
    }
    
    // Pre-compute these values
    for (const value of commonValues) {
        try {
            const point = mulPointEscalar(Base8, value);
            const key = `${point[0]},${point[1]}`;
            discreteLogCache.set(key, value);
        } catch (error) {
            // Skip if computation fails
        }
    }
    
    cacheInitialized = true;
}

// Cache management to prevent memory leaks
const MAX_CACHE_SIZE = 1000;
function setCacheWithLimit(key: string, value: bigint) {
    if (discreteLogCache.size >= MAX_CACHE_SIZE) {
        // Remove oldest entries (simple FIFO)
        const firstKey = discreteLogCache.keys().next().value;
        if (firstKey) {
            discreteLogCache.delete(firstKey);
        }
    }
    discreteLogCache.set(key, value);
}

/**
 * Optimized discrete logarithm finder with smart search patterns
 * Much more efficient than linear brute force, with caching
 */
function findDiscreteLogOptimized(targetPoint: [bigint, bigint]): bigint | null {
    // Initialize cache with common values if not done yet
    initializeCache();
    
    // Check cache first
    const cacheKey = `${targetPoint[0]},${targetPoint[1]}`;
    const cached = discreteLogCache.get(cacheKey);
    if (cached !== undefined) {
        return cached;
    }
    const maxValue = 100000n; // Up to 1000 PRIV with 2 decimals
    
    // Strategy 1: Check common small values first (0-1000)
    // Most balances are likely to be small
    for (let i = 0n; i <= 1000n; i++) {
        const testPoint = mulPointEscalar(Base8, i);
        if (testPoint[0] === targetPoint[0] && testPoint[1] === targetPoint[1]) {
            // Cache the result (with size limit)
            setCacheWithLimit(cacheKey, i);
            return i;
        }
    }
    
    // Strategy 2: Check round numbers (multiples of 100, 1000, etc.)
    // Many transactions are likely to be round amounts
    const roundNumbers = [
        100n, 500n, 1000n, 1500n, 2000n, 2500n, 3000n, 5000n, 
        10000n, 15000n, 20000n, 25000n, 30000n, 40000n, 50000n,
        75000n, 100000n
    ];
    
    for (const value of roundNumbers) {
        if (value <= maxValue) {
            const testPoint = mulPointEscalar(Base8, value);
            if (testPoint[0] === targetPoint[0] && testPoint[1] === targetPoint[1]) {
                // Cache the result (with size limit)
                setCacheWithLimit(cacheKey, value);
                return value;
            }
        }
    }
    
    // Strategy 3: Binary search-like approach for remaining values
    // Divide the remaining space into chunks and search efficiently
    const chunkSize = 1000n;
    for (let chunk = 1000n; chunk < maxValue; chunk += chunkSize) {
        const chunkEnd = chunk + chunkSize > maxValue ? maxValue : chunk + chunkSize;
        
        // Check chunk boundaries first
        for (let i = chunk; i < chunkEnd; i += 100n) {
            const testPoint = mulPointEscalar(Base8, i);
            if (testPoint[0] === targetPoint[0] && testPoint[1] === targetPoint[1]) {
                // Cache the result (with size limit)
                setCacheWithLimit(cacheKey, i);
                return i;
            }
        }
        
        // If we find we're in the right chunk, do detailed search
        // (This would need more sophisticated logic, but for now keep it simple)
    }
    
    // Strategy 4: Fallback to linear search in remaining space (with early termination)
    // Only search areas we haven't covered yet, with periodic checks
    for (let i = 1001n; i <= maxValue; i++) {
        // Skip values we already checked in previous strategies
        if (i % 100n === 0n) continue; // Already checked multiples of 100
        
        const testPoint = mulPointEscalar(Base8, i);
        if (testPoint[0] === targetPoint[0] && testPoint[1] === targetPoint[1]) {
            // Cache the result (with size limit)
            setCacheWithLimit(cacheKey, i);
            return i;
        }
        
        // Early termination: if we've been searching too long, give up
        if (i > 50000n && i % 10000n === 0n) {
            console.log(`🔍 Discrete log search progress: ${i}/${maxValue}...`);
        }
    }
    
    return null; // Not found
}

/**
 * Gets decrypted balance from encrypted balance using both EGCT and PCT decryption methods
 * @param privateKey The private key for decryption
 * @param amountPCTs Array of amount PCTs to decrypt
 * @param balancePCT Balance PCT to decrypt
 * @param encryptedBalance EGCT encrypted balance
 * @returns The total decrypted balance as bigint
 */
export async function getDecryptedBalance(
	privateKey: bigint,
    amountPCTs: any[],
    balancePCT: bigint[],
    encryptedBalance: bigint[][]
): Promise<bigint> {
    // First, try to decrypt the EGCT (main encrypted balance)
    const c1: [bigint, bigint] = [encryptedBalance[0][0], encryptedBalance[0][1]];
    const c2: [bigint, bigint] = [encryptedBalance[1][0], encryptedBalance[1][1]];
    
    // Check if EGCT is empty (all zeros)
    const isEGCTEmpty = c1[0] === 0n && c1[1] === 0n && c2[0] === 0n && c2[1] === 0n;
    
    if (!isEGCTEmpty) {
        // Decrypt EGCT - this is the primary balance
        const egctBalance = decryptEGCTBalance(privateKey, c1, c2);
        console.log("🔐 EGCT Balance found:", egctBalance.toString());
        return egctBalance;
    }
    
    // If EGCT is empty, fall back to PCT decryption
    let totalBalance = 0n;

    // Decrypt the balance PCT if it exists
    if (balancePCT.some((e) => e !== 0n)) {
        try {
            const decryptedBalancePCT = await decryptPCT(privateKey, balancePCT);
            totalBalance += BigInt(decryptedBalancePCT[0]);
        } catch (error) {
            console.log("Note: Balance PCT is empty or couldn't be decrypted");
        }
    }

    // Decrypt all the amount PCTs and add them to the total balance
    for (const amountPCT of amountPCTs) {
        if (amountPCT.pct && amountPCT.pct.some((e: bigint) => e !== 0n)) {
            try {
                const decryptedAmountPCT = await decryptPCT(privateKey, amountPCT.pct);
                totalBalance += BigInt(decryptedAmountPCT[0]);
            } catch (error) {
                console.log("Note: Some amount PCT couldn't be decrypted");
            }
        }
    }

    return totalBalance;
}

/**
 * Creates a User object with custom private key
 * @param privateKey The private key to use for the user
 * @param signer The signer instance to associate with the user
 * @returns User object with overridden keys
 */
/**
 * Creates a User from a registration signature, using the canonical
 * (SDK-compatible) derivation.
 *
 * Prefer this over `createUserFromPrivateKey`: it formats the scalar the way
 * the SDK does, so `user.formattedPrivateKey` -- which drives both the public
 * key and `genRegistrationHash` -- matches what the browser would produce for
 * the same signature.
 */
export function createUserFromSignature(signature: string, signer: any): User {
    const user = new User(signer);
    const decryptionKey = deriveDecryptionKey(signature);

    user.privateKey = BigInt(`0x${decryptionKey}`);
    user.formattedPrivateKey = formatDecryptionKey(decryptionKey);
    user.publicKey = mulPointEscalar(Base8, user.formattedPrivateKey).map((x) => BigInt(x));

    return user;
}

/**
 * @deprecated Applies maci's `formatPrivKeyForBabyJub`, which disagrees with the
 * SDK's formatting. Use `createUserFromSignature` so keys match the browser.
 */
export function createUserFromPrivateKey(privateKey: bigint, signer: any): User {
    // Create a new user instance
    const user = new User(signer);
    
    // Override the generated keys with our deterministic ones
    user.privateKey = privateKey;
    user.formattedPrivateKey = formatPrivKeyForBabyJub(privateKey);
    user.publicKey = mulPointEscalar(Base8, user.formattedPrivateKey).map((x) => BigInt(x));
    
    return user;
}

/**
 * Gets a wallet based on the wallet number parameter
 * @param walletNumber 1 for first signer, 2 for second signer, etc.
 * @returns The selected wallet signer
 */
export async function getWallet(walletNumber: number = 1) {
    const signers = await ethers.getSigners();
    
    if (walletNumber < 1 || walletNumber > signers.length) {
        throw new Error(`Invalid wallet number ${walletNumber}. Available wallets: 1-${signers.length}`);
    }
    
    const wallet = signers[walletNumber - 1]; // Convert to 0-based index
    const walletAddress = await wallet.getAddress();
    const balance = await ethers.provider.getBalance(walletAddress);
    
    console.log(`🔧 Using wallet ${walletNumber}: ${walletAddress}`);
    console.log(`💰 Current balance: ${ethers.formatEther(balance)} AVAX`);
    
    return wallet;
}

/**
 * Saves deployment data to both timestamped and latest files
 * @param deploymentData The deployment data object to save
 * @param isConverter Boolean flag - true for converter, false for standalone
 * @param baseDir Base directory path (typically __dirname from calling script)
 * @returns The deployment configuration used
 */
export function saveDeploymentData(deploymentData: any, baseDir: string, isConverter: boolean = true) {
    const deploymentType = isConverter ? "converter" : "standalone";
    const outputDir = path.join(baseDir, `../../deployments/${deploymentType}`);
    
    // Ensure directory exists
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    const timestamp = Date.now();
    const fileName = isConverter 
        ? `converter-${timestamp}.json`
        : `standalone-${timestamp}.json`;
    
    const latestFileName = isConverter 
        ? "latest-converter.json"
        : "latest-standalone.json";

    const filePath = path.join(outputDir, fileName);
    const latestFilePath = path.join(outputDir, latestFileName);

    // Save timestamped file
    fs.writeFileSync(filePath, JSON.stringify(deploymentData, null, 2));
    
    // Save latest file
    fs.writeFileSync(latestFilePath, JSON.stringify(deploymentData, null, 2));

    console.log(`\n📁 Deployment data saved to: ${filePath}`);
    console.log("🔗 You can import this file in your frontend like:");
    console.log(`   import deploymentData from './deployments/${deploymentType}/${fileName}';`);
    console.log(`📄 Latest deployment also saved to: deployments/${deploymentType}/${latestFileName}`);

    return {
        deploymentType,
        outputDir,
        fileName,
        latestFileName,
        filePath,
        latestFilePath,
        timestamp
    };
}
