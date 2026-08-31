import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import { decryptPCT } from "../../test/helpers";
import { getWallet, deriveKeysFromUser, decryptEGCTBalanceWithFormattedKey } from "../../src/utils";
import { formatDecryptionKey } from "../../src/utils/keyDerivation";
import { mulPointEscalar, Base8 } from "@zk-kit/baby-jubjub";
import { formatPrivKeyForBabyJub } from "maci-crypto";
const main = async () => {
    // Configure which wallet to use: 1 for first signer, 2 for second signer
    const WALLET_NUMBER = Number(process.env.WALLET_NUMBER ?? 1);
    
    const wallet = await getWallet(WALLET_NUMBER);
    const userAddress = await wallet.getAddress();
    
    // Read addresses from the latest deployment
    const deploymentPath = path.join(__dirname, "../../deployments/converter/latest-converter.json");
    const deploymentData = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
    
    const encryptedERCAddress = deploymentData.contracts.encryptedERC;
    const testERC20Address = deploymentData.contracts.testERC20;
    const registrarAddress = deploymentData.contracts.registrar;
    
    console.log("🔍 Checking encrypted balance for user...");
    console.log("User address:", userAddress);
    console.log("EncryptedERC:", encryptedERCAddress);
    console.log("TestERC20:", testERC20Address);
    
    // Connect to contracts
    const testERC20 = await ethers.getContractAt("SimpleERC20", testERC20Address, wallet);
    const encryptedERC = await ethers.getContractAt("EncryptedERC", encryptedERCAddress, wallet);
    const registrar = await ethers.getContractAt("Registrar", registrarAddress, wallet);
    
    try {
        // Check if user is registered
        const isRegistered = await registrar.isUserRegistered(userAddress);
        if (!isRegistered) {
            console.error("❌ User is not registered. Please run the registration script first.");
            console.log("💡 Run: npm run register:user");
            return;
        }
        console.log("✅ User is registered");
        
        // Try to load keys from saved file first
        let userPrivateKey: bigint;
        let formattedPrivateKey: bigint;
        let signature: string;
        
        const keysPath = path.join(__dirname, "../../deployments/converter/user-keys.json");
        if (fs.existsSync(keysPath)) {
            console.log("🔑 Loading keys from saved file...");
            const keysData = JSON.parse(fs.readFileSync(keysPath, "utf8"));
            
            if (keysData.userAddress === userAddress && keysData.keysMatch) {
                userPrivateKey = BigInt(keysData.privateKey);
                // Format with the SDK's scheme, not maci's -- a cached key must
                // still produce the scalar the browser would.
                formattedPrivateKey = formatDecryptionKey(userPrivateKey.toString(16));
                signature = keysData.signature;
                console.log("✅ Keys loaded from file");
            } else {
                console.log("⚠️  Saved keys mismatch, generating new keys...");
                const keys = await deriveKeysFromUser(userAddress, wallet);
                userPrivateKey = keys.privateKey;
                formattedPrivateKey = keys.formattedPrivateKey;
                signature = keys.signature;
            }
        } else {
            console.log("🔐 Generating keys for balance decryption...");
            const keys = await deriveKeysFromUser(userAddress, wallet);
            userPrivateKey = keys.privateKey;
            formattedPrivateKey = keys.formattedPrivateKey;
            signature = keys.signature;
        }
        
        console.log("🔑 Private key ready for decryption");
        
        // Get user's public key for verification
        const userPublicKey = await registrar.getUserPublicKey(userAddress);
        const derivedPublicKey = mulPointEscalar(Base8, formattedPrivateKey);
        
        const publicKeysMatch = derivedPublicKey[0] === BigInt(userPublicKey[0].toString()) && 
                               derivedPublicKey[1] === BigInt(userPublicKey[1].toString());
        if (publicKeysMatch) {
            console.log("✅ Private key matches registered public key");
        } else {
            console.log("❌ Private key doesn't match registered public key - decryption will fail!");
            console.log("💡 Run: npm run register:user to fix this");
            return;
        }
        
        // Check public token balance for reference
        const tokenBalance = await testERC20.balanceOf(userAddress);
        const tokenDecimals = await testERC20.decimals();
        const tokenSymbol = await testERC20.symbol();
        console.log(`💰 Public ${tokenSymbol} balance:`, ethers.formatUnits(tokenBalance, tokenDecimals), tokenSymbol);
        
        // Get token ID for testERC20
        let tokenId = 0n;
        try {
            tokenId = await encryptedERC.tokenIds(testERC20Address);
            console.log("📋 Token ID in EncryptedERC:", tokenId.toString());
            if (tokenId === 0n) {
                console.log("📋 Token not registered in EncryptedERC yet - no encrypted balance");
                console.log("💡 Make a deposit first: npm run deposit");
                return;
            }
        } catch (error) {
            console.log("📋 Token not registered in EncryptedERC - no encrypted balance");
            console.log("💡 Make a deposit first: npm run deposit");
            return;
        }
        
        // Get encrypted balance components using balanceOf function
        console.log("🔍 Reading encrypted balance from contract...");
        const [eGCT, nonce, amountPCTs, balancePCT, transactionIndex] = await encryptedERC.balanceOf(userAddress, tokenId);
        
        console.log("📋 Balance Details:");
        console.log("  - Transaction Index:", transactionIndex.toString());
        console.log("  - Nonce:", nonce.toString());
        console.log("  - Number of Amount PCTs:", amountPCTs.length);
        
        // Check if EGCT is empty (all zeros)
        const isEGCTEmpty = eGCT.c1.x === 0n && eGCT.c1.y === 0n && eGCT.c2.x === 0n && eGCT.c2.y === 0n;
        if (isEGCTEmpty) {
            console.log("📋 EGCT is empty (all zeros) - no main encrypted balance found");
            
            // Check amount PCTs to see if there are any transactions
            if (amountPCTs.length > 0) {
                console.log("🔍 Found Amount PCTs, checking transaction history...");
                let totalFromPCTs = 0n;
                
                for (let i = 0; i < amountPCTs.length; i++) {
                    const amountPCT = amountPCTs[i];
                    
                    try {
                        if (amountPCT.pct.some((e: bigint) => e !== 0n)) {
                            const decryptedAmount = await decryptPCT(userPrivateKey, amountPCT.pct.map(x => BigInt(x.toString())));
                            console.log(`  - Amount PCT ${i}: ${decryptedAmount[0].toString()} (index: ${amountPCT.index})`);
                            totalFromPCTs += BigInt(decryptedAmount[0]);
                        }
                    } catch (error) {
                        console.log(`  - Amount PCT ${i}: Failed to decrypt`);
                    }
                }
                
                if (totalFromPCTs > 0n) {
                    const encryptedSystemDecimals = 2;
                    console.log(`\n🔒 Total from Amount PCTs: ${ethers.formatUnits(totalFromPCTs, encryptedSystemDecimals)} encrypted units`);
                } else {
                    console.log("📋 No valid amounts found in PCTs");
                }
            } else {
                console.log("📋 No Amount PCTs found - user has no transaction history");
            }
            
            return;
        }
        
        // Decrypt EGCT using ElGamal decryption
        console.log("🔐 Decrypting EGCT using ElGamal...");
        const c1: [bigint, bigint] = [BigInt(eGCT.c1.x.toString()), BigInt(eGCT.c1.y.toString())];
        const c2: [bigint, bigint] = [BigInt(eGCT.c2.x.toString()), BigInt(eGCT.c2.y.toString())];
        
        console.log("  - EGCT C1:", [c1[0].toString(), c1[1].toString()]);
        console.log("  - EGCT C2:", [c2[0].toString(), c2[1].toString()]);
        
        const egctBalance = decryptEGCTBalanceWithFormattedKey(formattedPrivateKey, c1, c2);
        console.log("💰 EGCT Balance (raw):", egctBalance.toString());
        
        // Convert to display units (encrypted system uses 2 decimals)
        const encryptedSystemDecimals = 2;
        console.log(`🔒 EGCT Balance: ${ethers.formatUnits(egctBalance, encryptedSystemDecimals)} encrypted units`);
        
        // Also decrypt PCTs for comparison
        let totalFromPCTs = 0n;
        
        // Decrypt balance PCT if it exists
        if (balancePCT.some((e: any) => BigInt(e.toString()) !== 0n)) {
            try {
                const balancePCTArray = balancePCT.map((x: any) => BigInt(x.toString()));
                const decryptedBalancePCT = await decryptPCT(userPrivateKey, balancePCTArray);
                console.log("💰 Balance PCT (decrypted):", decryptedBalancePCT[0].toString());
                totalFromPCTs += BigInt(decryptedBalancePCT[0]);
            } catch (error) {
                console.log("⚠️  Failed to decrypt balance PCT:", error);
            }
        }
        
        // Decrypt all amount PCTs
        if (amountPCTs.length > 0) {
            console.log("🔍 Decrypting Amount PCTs...");
            for (let i = 0; i < amountPCTs.length; i++) {
                const amountPCT = amountPCTs[i];
                try {
                    if (amountPCT.pct.some((e: bigint) => e !== 0n)) {
                        const decryptedAmount = await decryptPCT(userPrivateKey, amountPCT.pct.map(x => BigInt(x.toString())));
                        console.log(`  - Amount PCT ${i}: ${decryptedAmount[0].toString()} (index: ${amountPCT.index})`);
                        totalFromPCTs += BigInt(decryptedAmount[0]);
                    }
                } catch (error) {
                    console.log(`  - Amount PCT ${i}: Failed to decrypt`);
                }
            }
        }
        
        console.log("\n📊 Balance Summary:");
        console.log(`   EGCT Balance (main): ${ethers.formatUnits(egctBalance, encryptedSystemDecimals)} encrypted units`);
        if (totalFromPCTs > 0n) {
            console.log(`   Total from PCTs: ${ethers.formatUnits(totalFromPCTs, encryptedSystemDecimals)} encrypted units`);
        }
        console.log(`   Public ${tokenSymbol} Balance: ${ethers.formatUnits(tokenBalance, tokenDecimals)} ${tokenSymbol}`);
        
        // Show equivalent values
        console.log("\n💡 Balance Explanation:");
        console.log(`   • EGCT Balance: Your main encrypted balance stored on-chain`);
        console.log(`   • Amount PCTs: Transaction history for auditing purposes`);
        console.log(`   • Public Balance: Your regular ${tokenSymbol} tokens (not encrypted)`);
        console.log(`   • Encrypted System: Uses ${encryptedSystemDecimals} decimal places internally`);
        
        // Verify consistency
        if (egctBalance !== totalFromPCTs && totalFromPCTs > 0n) {
            console.log("\n⚠️  Warning: EGCT balance doesn't match PCT total");
            console.log("   This might indicate an issue with the encryption/decryption process");
        } else if (egctBalance === totalFromPCTs && egctBalance > 0n) {
            console.log("\n✅ EGCT balance matches PCT total - encryption is consistent");
        }
        
        // Update keys if needed
        if (!fs.existsSync(keysPath) || JSON.parse(fs.readFileSync(keysPath, "utf8")).userAddress !== userAddress) {
            const keysData = {
                userAddress,
                signature,
                privateKey: userPrivateKey.toString(),
                formattedPrivateKey: formattedPrivateKey.toString(),
                publicKey: [derivedPublicKey[0].toString(), derivedPublicKey[1].toString()],
                lastUpdated: new Date().toISOString(),
                note: "Keys for decrypting encrypted balances in EncryptedERC",
                keysMatch: true
            };
            
            fs.writeFileSync(keysPath, JSON.stringify(keysData, null, 2));
            console.log(`\n🔑 Keys saved/updated: ${keysPath}`);
        }
        
    } catch (error) {
        console.error("❌ Error checking balance:");
        console.error(error);
        
        if (error instanceof Error) {
            if (error.message.includes("User not registered")) {
                console.error("💡 Hint: Register your user first with: npm run register:user");
            } else if (error.message.includes("execution reverted")) {
                console.error("💡 Hint: This might be a contract or network issue");
            }
        }
        
        throw error;
    }
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});