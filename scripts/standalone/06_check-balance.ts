import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import { decryptPCT } from "../../test/helpers";
import { getWallet, deriveKeysFromUser, decryptEGCTBalanceWithFormattedKey } from "../../src/utils";

const main = async () => {
    // Which signer to act as. The env var is the documented control -- this used

    // to be a hardcoded constant with a comment claiming otherwise, so following

    // the README's "update .env for each user" silently kept using wallet 1.
    const WALLET_NUMBER = Number(process.env.WALLET_NUMBER ?? 1);
    
    const wallet = await getWallet(WALLET_NUMBER);
    const userAddress = await wallet.getAddress();
    
    // Read addresses from the latest standalone deployment
    const deploymentPath = path.join(__dirname, "../../deployments/standalone/latest-standalone.json");
    const deploymentData = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
    
    const encryptedERCAddress = deploymentData.contracts.encryptedERC;
    const registrarAddress = deploymentData.contracts.registrar;
    
    console.log("💰 Checking Encrypted Balance in Standalone EncryptedERC...");
    console.log("EncryptedERC:", encryptedERCAddress);
    console.log("User:", userAddress);
    
    // Connect to contracts
    const encryptedERC = await ethers.getContractAt("EncryptedERC", encryptedERCAddress, wallet);
    const registrar = await ethers.getContractAt("Registrar", registrarAddress, wallet);
    
    try {
        // Check if user is registered
        const isUserRegistered = await registrar.isUserRegistered(userAddress);
        if (!isUserRegistered) {
            console.error("❌ User is not registered. Please run the registration script first.");
            console.log("💡 Run: npx hardhat run scripts/standalone/03_register-user.ts --network fuji");
            return;
        }
        console.log("✅ User is registered");
        
        // Derive keys from user signature (same as other scripts)
        console.log("🔑 Deriving keys from user signature...");
        const { privateKey: userPrivateKey, formattedPrivateKey, publicKey, signature } = await deriveKeysFromUser(userAddress, wallet);
        
        // Verify with smart contract
        const userPublicKey = await registrar.getUserPublicKey(userAddress);
        const publicKeysMatch = publicKey[0] === BigInt(userPublicKey[0].toString()) && 
                               publicKey[1] === BigInt(userPublicKey[1].toString());
        if (!publicKeysMatch) {
            console.error("❌ Private key doesn't match registered public key - decryption will fail!");
            console.log("💡 Run: npx hardhat run scripts/standalone/03_register-user.ts --network fuji to fix this");
            return;
        }
        console.log("✅ Private key matches registered public key");
        
        // Get token information
        const tokenName = await encryptedERC.name();
        const tokenSymbol = await encryptedERC.symbol();
        const tokenDecimals = await encryptedERC.decimals();
        
        console.log(`\n📋 Token Details:`);
        console.log(`   Name: ${tokenName}`);
        console.log(`   Symbol: ${tokenSymbol}`);
        console.log(`   Decimals: ${tokenDecimals}`);
        
        // For standalone mode, tokenId is always 0
        const tokenId = 0n;
        
        // Get encrypted balance components using balanceOf function
        console.log("\n🔍 Reading encrypted balance from contract...");
        const [eGCT, nonce, amountPCTs, balancePCT, transactionIndex] = await encryptedERC.balanceOf(userAddress, tokenId);
        
        console.log("📋 Balance Details:");
        console.log("  - Transaction Index:", transactionIndex.toString());
        console.log("  - Nonce:", nonce.toString());
        console.log("  - Number of Amount PCTs:", amountPCTs.length);
        
        // Calculate balance using proper method (handles large balances correctly)
        console.log("🔐 Calculating current balance...");
        
        const c1: [bigint, bigint] = [BigInt(eGCT.c1.x.toString()), BigInt(eGCT.c1.y.toString())];
        const c2: [bigint, bigint] = [BigInt(eGCT.c2.x.toString()), BigInt(eGCT.c2.y.toString())];
        
        const isEGCTEmpty = c1[0] === 0n && c1[1] === 0n && c2[0] === 0n && c2[1] === 0n;
        
        let userCurrentBalance = 0n;
        let balanceSource = "none";
        
        if (!isEGCTEmpty) {
            // Try EGCT decryption first (works for balances up to 1000 PRIV/100000 raw units)
            userCurrentBalance = decryptEGCTBalanceWithFormattedKey(formattedPrivateKey, c1, c2);
            console.log("🔐 EGCT decryption result:", userCurrentBalance.toString());
            if (userCurrentBalance > 0n) {
                balanceSource = "EGCT";
            }
        }
        
        // If EGCT failed or is empty, calculate from PCTs (fallback for large balances)
        if (userCurrentBalance === 0n && (isEGCTEmpty || amountPCTs.length > 0)) {
            console.log("🔄 EGCT empty or failed, calculating from transaction history...");
            
            // Calculate balance from balance PCT
            if (balancePCT.some((e: any) => BigInt(e.toString()) !== 0n)) {
                try {
                    const balancePCTArray = balancePCT.map((x: any) => BigInt(x.toString()));
                    const decryptedBalancePCT = await decryptPCT(userPrivateKey, balancePCTArray);
                    userCurrentBalance += BigInt(decryptedBalancePCT[0]);
                    console.log("📝 Balance from balance PCT:", decryptedBalancePCT[0].toString());
                } catch (error) {
                    console.log("⚠️  Could not decrypt balance PCT");
                }
            }
            
            // Add amounts from amount PCTs
            for (let i = 0; i < amountPCTs.length; i++) {
                const amountPCT = amountPCTs[i];
                try {
                    if (amountPCT.pct.some((e: bigint) => e !== 0n)) {
                        const decryptedAmount = await decryptPCT(userPrivateKey, amountPCT.pct.map(x => BigInt(x.toString())));
                        userCurrentBalance += BigInt(decryptedAmount[0]);
                        console.log(`📈 Added from PCT ${i+1}:`, decryptedAmount[0].toString());
                    }
                } catch (error) {
                    console.log(`⚠️  Could not decrypt amount PCT ${i+1}`);
                }
            }
            
            if (userCurrentBalance > 0n) {
                balanceSource = "PCTs";
            }
        }
        
        if (userCurrentBalance === 0n && !isEGCTEmpty) {
            console.log("⚠️  Balance decryption failed - this might indicate the balance exceeds 1000 PRIV");
            console.log("💡 Very large balances use PCT calculation as fallback");
        }
        
        console.log(`\n💰 Current Balance: ${ethers.formatUnits(userCurrentBalance, tokenDecimals)} ${tokenSymbol}`);
        
        // Show transaction history (PCTs) for audit purposes
        console.log("\n📋 Transaction History (for compliance/audit):");
        
        let transactionCount = 0;
        
        // Check balance PCT
        if (balancePCT.some((e: any) => BigInt(e.toString()) !== 0n)) {
            try {
                const balancePCTArray = balancePCT.map((x: any) => BigInt(x.toString()));
                const decryptedBalancePCT = await decryptPCT(userPrivateKey, balancePCTArray);
                console.log(`  📝 Balance PCT: ${ethers.formatUnits(decryptedBalancePCT[0], tokenDecimals)} ${tokenSymbol}`);
                transactionCount++;
            } catch (error) {
                console.log("  📝 Balance PCT: Could not decrypt");
            }
        }
        
        // Check amount PCTs
        if (amountPCTs.length > 0) {
            console.log(`  📈 Amount PCTs (${amountPCTs.length} records):`);
            for (let i = 0; i < amountPCTs.length; i++) {
                const amountPCT = amountPCTs[i];
                try {
                    if (amountPCT.pct.some((e: bigint) => e !== 0n)) {
                        const decryptedAmount = await decryptPCT(userPrivateKey, amountPCT.pct.map(x => BigInt(x.toString())));
                        console.log(`    - Transaction ${i+1}: ${ethers.formatUnits(decryptedAmount[0], tokenDecimals)} ${tokenSymbol} (index: ${amountPCT.index})`);
                        transactionCount++;
                    }
                } catch (error) {
                    console.log(`    - Transaction ${i+1}: Could not decrypt`);
                }
            }
        } else {
            console.log("  📝 No Amount PCTs found");
        }
        
        if (transactionCount === 0) {
            console.log("  📝 No transaction history found");
        }
        
        console.log(`\n✅ Balance Check Complete!`);
        console.log(`💰 Spendable Balance: ${ethers.formatUnits(userCurrentBalance, tokenDecimals)} ${tokenSymbol}`);
        console.log(`📋 Transaction Records: ${transactionCount} audit records found`);
        
        console.log("\n💡 Balance Information:");
        console.log(`   • Spendable balance: ${ethers.formatUnits(userCurrentBalance, tokenDecimals)} ${tokenSymbol}`);
        console.log(`   • Balance source: ${balanceSource === "EGCT" ? "EGCT encryption" : balanceSource === "PCTs" ? "PCT transaction history" : "No balance found"}`);
        console.log(`   • Transaction records: ${transactionCount} audit records found`);
        console.log(`   • All data is privately encrypted - only you can decrypt it`);
        console.log(`   • This balance can be used for transfers and burns`);
        
    } catch (error) {
        console.error("❌ Error checking balance:");
        console.error(error);
        
        if (error instanceof Error) {
            if (error.message.includes("User not registered")) {
                console.error("💡 Hint: Register your user first with: npx hardhat run scripts/standalone/03_register-user.ts --network fuji");
            } else if (error.message.includes("execution reverted")) {
                console.error("💡 Hint: This might be a contract or network issue");
            } else if (error.message.includes("cannot decrypt")) {
                console.error("💡 Hint: Your private key might not match the registered public key");
            }
        }
        
        throw error;
    }
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});