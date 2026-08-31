import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import { withdraw } from "../../test/helpers";
import { createUserFromSignature, decryptEGCTBalanceWithFormattedKey, getWallet } from "../../src/utils";
import { formatPrivKeyForBabyJub } from "maci-crypto";
import { mulPointEscalar, Base8 } from "@zk-kit/baby-jubjub";

const main = async () => {
    // Which signer to act as. The env var is the documented control -- this used

    // to be a hardcoded constant with a comment claiming otherwise, so following

    // the README's "update .env for each user" silently kept using wallet 1.
    const WALLET_NUMBER = Number(process.env.WALLET_NUMBER ?? 1);
    
    const wallet = await getWallet(WALLET_NUMBER);
    const userAddress = await wallet.getAddress();
    
    // Hardcoded withdrawal amount (you can change this)
    const withdrawAmountStr = "40"; // Amount to withdraw
    
    console.log("💸 Withdrawing encrypted tokens to regular ERC20...");
    console.log("User address:", userAddress);
    console.log("Withdraw amount:", withdrawAmountStr);
    
    // Read addresses from the latest deployment
    const deploymentPath = path.join(__dirname, "../../deployments/converter/latest-converter.json");
    const deploymentData = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
    
    const encryptedERCAddress = deploymentData.contracts.encryptedERC;
    const testERC20Address = deploymentData.contracts.testERC20;
    const registrarAddress = deploymentData.contracts.registrar;
    
    console.log("EncryptedERC:", encryptedERCAddress);
    console.log("TestERC20:", testERC20Address);
    
    // Connect to contracts
    const testERC20 = await ethers.getContractAt("SimpleERC20", testERC20Address, wallet);
    const encryptedERC = await ethers.getContractAt("EncryptedERC", encryptedERCAddress, wallet);
    const registrar = await ethers.getContractAt("Registrar", registrarAddress, wallet);
    
    try {
        // Check if user is registered
        const isUserRegistered = await registrar.isUserRegistered(userAddress);
        if (!isUserRegistered) {
            console.error("❌ User is not registered. Please run the registration script first.");
            console.log("💡 Run: npm run register:user");
            return;
        }
        console.log("✅ User is registered");
        
        // Load or generate user's keys
        let signature: string;
        
        const keysPath = path.join(__dirname, "../../deployments/converter/user-keys.json");
        if (fs.existsSync(keysPath)) {
            console.log("🔑 Loading keys from saved file...");
            const keysData = JSON.parse(fs.readFileSync(keysPath, "utf8"));
            
            if (keysData.userAddress === userAddress && keysData.keysMatch) {
                signature = keysData.signature;
                console.log("✅ Keys loaded from file");
            } else {
                console.log("⚠️  Saved keys mismatch, generating new signature...");
                const message = `eERC
Registering user with
 Address:${userAddress.toLowerCase()}`;
                signature = await wallet.signMessage(message);
            }
        } else {
            console.log("🔐 Generating signature for withdrawal...");
            const message = `eERC
Registering user with
 Address:${userAddress.toLowerCase()}`;
            signature = await wallet.signMessage(message);
        }
        
        // Create user object for proof generation
        const user = createUserFromSignature(signature, wallet);
        
        // Get public keys
        const userPublicKey = await registrar.getUserPublicKey(userAddress);
        const auditorPublicKey = await encryptedERC.auditorPublicKey();
        
        console.log("🔑 User public key:", [userPublicKey[0].toString(), userPublicKey[1].toString()]);
        console.log("🔑 Auditor public key:", [auditorPublicKey[0].toString(), auditorPublicKey[1].toString()]);
        
        // Verify user's keys match
        const derivedPublicKey = user.publicKey;
        const keysMatch = derivedPublicKey[0] === BigInt(userPublicKey[0].toString()) && 
                         derivedPublicKey[1] === BigInt(userPublicKey[1].toString());
        
        if (!keysMatch) {
            console.error("❌ User's private key doesn't match registered public key!");
            console.log("💡 Run: npm run register:user to fix this");
            return;
        }
        console.log("✅ User keys verified");
        
        // Get token ID
        const tokenId = await encryptedERC.tokenIds(testERC20Address);
        if (tokenId === 0n) {
            console.error("❌ Token not registered in EncryptedERC yet. Make a deposit first.");
            console.log("💡 Run: npm run deposit");
            return;
        }
        console.log("📋 Token ID:", tokenId.toString());
        
        // Get user's current encrypted balance
        console.log("🔍 Getting user's encrypted balance...");
        const [eGCT, nonce, amountPCTs, balancePCT, transactionIndex] = await encryptedERC.balanceOf(userAddress, tokenId);
        
        // Decrypt user's balance using EGCT
        const c1: [bigint, bigint] = [BigInt(eGCT.c1.x.toString()), BigInt(eGCT.c1.y.toString())];
        const c2: [bigint, bigint] = [BigInt(eGCT.c2.x.toString()), BigInt(eGCT.c2.y.toString())];
        
        const isEGCTEmpty = c1[0] === 0n && c1[1] === 0n && c2[0] === 0n && c2[1] === 0n;
        if (isEGCTEmpty) {
            console.error("❌ User has no encrypted balance to withdraw");
            console.log("💡 Make a deposit first: npm run deposit");
            return;
        }
        
        const userCurrentBalance = decryptEGCTBalanceWithFormattedKey(user.formattedPrivateKey, c1, c2);
        const encryptedSystemDecimals = 2;
        
        console.log(`💰 Current encrypted balance: ${ethers.formatUnits(userCurrentBalance, encryptedSystemDecimals)} encrypted units`);
        
        // Convert withdrawal amount to encrypted system units
        const withdrawAmount = parseFloat(withdrawAmountStr);
        if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
            throw new Error("❌ Invalid withdrawal amount");
        }
        
        const withdrawAmountBigInt = BigInt(Math.floor(withdrawAmount * (10 ** encryptedSystemDecimals)));
        
        if (userCurrentBalance < withdrawAmountBigInt) {
            console.error(`❌ Insufficient encrypted balance. Have: ${ethers.formatUnits(userCurrentBalance, encryptedSystemDecimals)}, Need: ${withdrawAmount}`);
            return;
        }
        
        console.log(`✅ Withdrawal amount: ${ethers.formatUnits(withdrawAmountBigInt, encryptedSystemDecimals)} encrypted units`);
        
        // Get current public token balance (before withdrawal)
        const tokenDecimals = await testERC20.decimals();
        const tokenSymbol = await testERC20.symbol();
        const publicTokenBalanceBefore = await testERC20.balanceOf(userAddress);
        console.log(`💰 Current public ${tokenSymbol} balance: ${ethers.formatUnits(publicTokenBalanceBefore, tokenDecimals)} ${tokenSymbol}`);
        
        // Prepare data for withdrawal proof generation
        const userEncryptedBalance = [c1[0], c1[1], c2[0], c2[1]];
        const auditorPublicKeyArray = [BigInt(auditorPublicKey[0].toString()), BigInt(auditorPublicKey[1].toString())];
        
        console.log("🔐 Generating withdrawal proof...");
        console.log("This may take a while...");
        
        // Generate withdrawal proof using the helper function
        const { proof, userBalancePCT } = await withdraw(
            withdrawAmountBigInt,
            user,
            userEncryptedBalance,
            userCurrentBalance,
            auditorPublicKeyArray
        );
        
        console.log("✅ Withdrawal proof generated successfully");
        
        // Format proof for contract call (proof is already in the correct format)
        const withdrawProof = proof;
        
        console.log("📝 Submitting withdrawal to contract...");
        
        // Call the contract's withdraw function
        const withdrawTx = await encryptedERC.withdraw(
            tokenId,
            withdrawProof,
            userBalancePCT
        );
        
        console.log("📝 Withdrawal transaction sent:", withdrawTx.hash);
        
        const receipt = await withdrawTx.wait();
        console.log("✅ Withdrawal transaction confirmed in block:", receipt?.blockNumber);
        
        console.log("🎉 Private withdrawal completed successfully!");
        
        // Show updated balances
        console.log("\n🔍 Checking updated balances...");
        
        // Get user's new encrypted balance
        const [newEGCT] = await encryptedERC.balanceOf(userAddress, tokenId);
        const newC1: [bigint, bigint] = [BigInt(newEGCT.c1.x.toString()), BigInt(newEGCT.c1.y.toString())];
        const newC2: [bigint, bigint] = [BigInt(newEGCT.c2.x.toString()), BigInt(newEGCT.c2.y.toString())];
        
        let newEncryptedBalance = 0n;
        const isNewEGCTEmpty = newC1[0] === 0n && newC1[1] === 0n && newC2[0] === 0n && newC2[1] === 0n;
        if (!isNewEGCTEmpty) {
            newEncryptedBalance = decryptEGCTBalanceWithFormattedKey(user.formattedPrivateKey, newC1, newC2);
        }
        
        // Get new public token balance
        const publicTokenBalanceAfter = await testERC20.balanceOf(userAddress);
        const tokensReceived = publicTokenBalanceAfter - publicTokenBalanceBefore;
        
        console.log(`💰 New encrypted balance: ${ethers.formatUnits(newEncryptedBalance, encryptedSystemDecimals)} encrypted units`);
        console.log(`💰 New public ${tokenSymbol} balance: ${ethers.formatUnits(publicTokenBalanceAfter, tokenDecimals)} ${tokenSymbol}`);
        console.log(`📥 ${tokenSymbol} tokens received: ${ethers.formatUnits(tokensReceived, tokenDecimals)} ${tokenSymbol}`);
        
        console.log("\n🎯 Withdrawal Summary:");
        console.log(`   User: ${userAddress}`);
        console.log(`   Encrypted Amount Withdrawn: ${withdrawAmount} encrypted units`);
        console.log(`   Public ${tokenSymbol} Received: ${ethers.formatUnits(tokensReceived, tokenDecimals)} ${tokenSymbol}`);
        console.log(`   Transaction: ${withdrawTx.hash}`);
        
        console.log("\n💡 Your encrypted tokens have been converted back to regular ERC20 tokens!");
        
        // Update keys if needed
        if (!fs.existsSync(keysPath) || JSON.parse(fs.readFileSync(keysPath, "utf8")).userAddress !== userAddress) {
            const formattedPrivateKey = formatPrivKeyForBabyJub(userPrivateKey);
            const derivedPublicKey = mulPointEscalar(Base8, formattedPrivateKey);
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
        console.error("❌ Error during withdrawal:");
        console.error(error);
        
        if (error instanceof Error) {
            if (error.message.includes("User not registered")) {
                console.error("💡 Hint: Register your user first with: npm run register:user");
            } else if (error.message.includes("Auditor not set")) {
                console.error("💡 Hint: The auditor needs to be set in the EncryptedERC contract");
            } else if (error.message.includes("Contract is not in converter mode")) {
                console.error("💡 Hint: The EncryptedERC contract needs to be in converter mode for withdrawals");
            } else if (error.message.includes("InvalidProof")) {
                console.error("💡 Hint: The withdrawal proof verification failed - check inputs");
            }
        }
        
        throw error;
    }
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});