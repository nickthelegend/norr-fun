import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import { privateBurn } from "../../test/helpers";
import { createUserFromSignature, decryptEGCTBalanceWithFormattedKey, getWallet } from "../../src/utils";

const main = async () => {
    // Which signer to act as. The env var is the documented control -- this used

    // to be a hardcoded constant with a comment claiming otherwise, so following

    // the README's "update .env for each user" silently kept using wallet 1.
    const WALLET_NUMBER = Number(process.env.WALLET_NUMBER ?? 1);
    
    const wallet = await getWallet(WALLET_NUMBER);
    const userAddress = await wallet.getAddress();
    
    // Burn amount - let's burn 20 tokens (in encrypted system units)
    const burnAmount = BigInt(20 * 100); // 20 tokens with 2 decimal places
    
    console.log("🔥 Private Burn in Standalone EncryptedERC...");
    console.log("User:", userAddress);
    console.log("Amount to burn:", ethers.formatUnits(burnAmount, 2), "PRIV tokens");
    
    // Read addresses from the latest standalone deployment
    const deploymentPath = path.join(__dirname, "../../deployments/standalone/latest-standalone.json");
    const deploymentData = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
    
    const encryptedERCAddress = deploymentData.contracts.encryptedERC;
    const registrarAddress = deploymentData.contracts.registrar;
    
    console.log("EncryptedERC:", encryptedERCAddress);
    console.log("Registrar:", registrarAddress);
    
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
        
        // Load or generate user's keys
        let signature: string;
        
        const keysPath = path.join(__dirname, "../../deployments/standalone/user-keys.json");
        if (fs.existsSync(keysPath)) {
            console.log("🔑 Loading user keys from saved file...");
            const keysData = JSON.parse(fs.readFileSync(keysPath, "utf8"));
            
            if (keysData.address === userAddress) {
                console.log("✅ User keys loaded from file");
            } else {
                console.log("⚠️  Saved keys mismatch, generating new signature...");
                const message = `eERC
Registering user with
 Address:${userAddress.toLowerCase()}`;
                signature = await wallet.signMessage(message);
            }
        } else {
            console.log("🔐 Generating signature for user...");
            const message = `eERC
Registering user with
 Address:${userAddress.toLowerCase()}`;
            signature = await wallet.signMessage(message);
        }
        
        // Create user User object
        const user = createUserFromSignature(signature, wallet);
        
        // Get public keys from registrar
        const userPublicKey = await registrar.getUserPublicKey(userAddress);
        const auditorPublicKey = await encryptedERC.auditorPublicKey();
        
        console.log("🔑 User public key:", [userPublicKey[0].toString(), userPublicKey[1].toString()]);
        console.log("🔑 Auditor public key:", [auditorPublicKey.x.toString(), auditorPublicKey.y.toString()]);
        
        // Verify user's keys match
        const derivedUserPublicKey = user.publicKey;
        const userKeysMatch = derivedUserPublicKey[0] === BigInt(userPublicKey[0].toString()) && 
                             derivedUserPublicKey[1] === BigInt(userPublicKey[1].toString());
        
        if (!userKeysMatch) {
            console.error("❌ User's private key doesn't match registered public key!");
            console.log("Run: npx hardhat run scripts/standalone/03_register-user.ts --network fuji");
            return;
        }
        console.log("✅ User keys verified");
        
        // For standalone mode, tokenId is always 0
        const tokenId = 0n;
        
        // Get user's current encrypted balance
        console.log("🔍 Getting user's encrypted balance...");
        const [eGCT, nonce, amountPCTs, balancePCT, transactionIndex] = await encryptedERC.balanceOf(userAddress, tokenId);
        
        // Decrypt user's balance using EGCT
        const c1: [bigint, bigint] = [BigInt(eGCT.c1.x.toString()), BigInt(eGCT.c1.y.toString())];
        const c2: [bigint, bigint] = [BigInt(eGCT.c2.x.toString()), BigInt(eGCT.c2.y.toString())];
        
        const isEGCTEmpty = c1[0] === 0n && c1[1] === 0n && c2[0] === 0n && c2[1] === 0n;
        if (isEGCTEmpty) {
            console.error("❌ User has no encrypted balance to burn");
            return;
        }
        
        const userCurrentBalance = decryptEGCTBalanceWithFormattedKey(user.formattedPrivateKey, c1, c2);
        const tokenDecimals = await encryptedERC.decimals();
        
        console.log(`💰 User's current balance: ${ethers.formatUnits(userCurrentBalance, tokenDecimals)} PRIV`);
        
        if (userCurrentBalance < burnAmount) {
            console.error(`❌ Insufficient balance to burn. Have: ${ethers.formatUnits(userCurrentBalance, tokenDecimals)}, Need: ${ethers.formatUnits(burnAmount, tokenDecimals)}`);
            return;
        }
        
        console.log(`✅ Burn amount: ${ethers.formatUnits(burnAmount, tokenDecimals)} PRIV tokens`);
        
        // Prepare data for burn proof generation
        const userEncryptedBalance = [c1[0], c1[1], c2[0], c2[1]];
        const auditorPublicKeyArray = [BigInt(auditorPublicKey.x.toString()), BigInt(auditorPublicKey.y.toString())];
        
        console.log("🔐 Generating burn proof...");
        console.log("⏳ This may take a while...");
        
        // Generate burn proof using the helper function
        const { proof, userBalancePCT } = await privateBurn(
            user,
            userCurrentBalance,
            burnAmount,
            userEncryptedBalance,
            auditorPublicKeyArray
        );
        
        console.log("✅ Burn proof generated successfully");
        
        // Debug the proof structure
        console.log("🔍 Debug: burn proof structure:", proof);
        
        // Use the proof directly (since privateBurn returns the correct calldata format)
        const burnProof = proof;
        
        console.log("📝 Submitting burn to contract...");
        
        // Call the contract's privateBurn function
        const burnTx = await encryptedERC.privateBurn(
            burnProof,
            userBalancePCT
        );
        
        console.log("📝 Burn transaction sent:", burnTx.hash);
        
        const receipt = await burnTx.wait();
        console.log("✅ Burn transaction confirmed in block:", receipt?.blockNumber);
        
        console.log("🎉 Private burn completed successfully!");
        
        // Show transaction details from events
        if (receipt) {
            const logs = receipt.logs;
            for (const log of logs) {
                try {
                    const parsed = encryptedERC.interface.parseLog(log);
                    if (parsed && parsed.name === "PrivateBurn") {
                        const [user, auditorPCT, auditorAddress] = parsed.args;
                        console.log("\n📋 Burn Details:");
                        console.log("  - User:", user);
                        console.log("  - Auditor:", auditorAddress);
                        console.log("  - Audit trail created for compliance");
                    }
                } catch (e) {
                    // Skip logs that can't be parsed by this contract
                }
            }
        }
        
        // Show updated balance
        console.log("\n🔍 Checking updated balance...");
        
        // Get user's new balance
        const [newEGCT] = await encryptedERC.balanceOf(userAddress, tokenId);
        const newC1: [bigint, bigint] = [BigInt(newEGCT.c1.x.toString()), BigInt(newEGCT.c1.y.toString())];
        const newC2: [bigint, bigint] = [BigInt(newEGCT.c2.x.toString()), BigInt(newEGCT.c2.y.toString())];
        
        // Check if new balance is empty
        const isNewEGCTEmpty = newC1[0] === 0n && newC1[1] === 0n && newC2[0] === 0n && newC2[1] === 0n;
        let userNewBalance = 0n;
        if (!isNewEGCTEmpty) {
            userNewBalance = decryptEGCTBalanceWithFormattedKey(user.formattedPrivateKey, newC1, newC2);
        }
        
        console.log(`💰 User's new balance: ${ethers.formatUnits(userNewBalance, tokenDecimals)} PRIV`);
        console.log(`🔥 Amount burned: ${ethers.formatUnits(burnAmount, tokenDecimals)} PRIV`);
        
        console.log("\n🎯 Burn Summary:");
        console.log(`   User: ${userAddress}`);
        console.log(`   Amount burned: ${ethers.formatUnits(burnAmount, tokenDecimals)} PRIV tokens`);
        console.log(`   Remaining balance: ${ethers.formatUnits(userNewBalance, tokenDecimals)} PRIV tokens`);
        console.log(`   Transaction: ${burnTx.hash}`);
        console.log(`   Status: Tokens permanently destroyed (burned)`);
        
        console.log("\n💡 Next Steps:");
        console.log("   • Check updated balance: npx hardhat run scripts/standalone/06_check-balance.ts --network fuji");
        console.log("   • Mint more tokens: npx hardhat run scripts/standalone/05_mint.ts --network fuji");
        
    } catch (error) {
        console.error("❌ Error during private burn:");
        console.error(error);
        
        if (error instanceof Error) {
            if (error.message.includes("User not registered")) {
                console.error("💡 Hint: The user must be registered first");
            } else if (error.message.includes("Auditor not set")) {
                console.error("💡 Hint: The auditor needs to be set in the EncryptedERC contract");
            } else if (error.message.includes("InvalidProof")) {
                console.error("💡 Hint: The burn proof verification failed - check inputs");
            } else if (error.message.includes("Insufficient balance")) {
                console.error("💡 Hint: User doesn't have enough tokens to burn");
            }
        }
        
        throw error;
    }
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});