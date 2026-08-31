import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import { privateTransfer } from "../../test/helpers";
import { createUserFromSignature, decryptEGCTBalanceWithFormattedKey, getWallet } from "../../src/utils";

const main = async () => {
    // Configure which wallets to use: 1 for first signer (sender), 2 for second signer (receiver)
    // Can be overridden with environment variables: SENDER_WALLET=1, RECEIVER_WALLET=2
    const SENDER_WALLET_NUMBER = 1;
    const RECEIVER_WALLET_NUMBER = 2;
    
    const wallet = await getWallet(SENDER_WALLET_NUMBER);
    const wallet2 = await getWallet(RECEIVER_WALLET_NUMBER);
    const senderAddress = await wallet.getAddress();
    const receiverAddress = await wallet2.getAddress();
    
    // Transfer amount - let's transfer 30 tokens (in encrypted system units)
    const transferAmount = BigInt(30 * 100); // 30 tokens with 2 decimal places
    
    console.log("🔄 Private Transfer in Standalone EncryptedERC...");
    console.log("Sender:", senderAddress);
    console.log("Receiver:", receiverAddress);
    console.log("Amount to transfer:", ethers.formatUnits(transferAmount, 2), "PRIV tokens");
    
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
        // Check if both sender and receiver are registered
        const isSenderRegistered = await registrar.isUserRegistered(senderAddress);
        const isReceiverRegistered = await registrar.isUserRegistered(receiverAddress);
        
        if (!isSenderRegistered) {
            console.error("❌ Sender is not registered. Please run the registration script first.");
            return;
        }
        if (!isReceiverRegistered) {
            console.error("❌ Receiver is not registered. They need to register first.");
            return;
        }
        
        console.log("✅ Both sender and receiver are registered");
        
        // Load or generate sender's keys
        let signature: string;
        
        const keysPath = path.join(__dirname, "../../deployments/standalone/user-keys.json");
        if (fs.existsSync(keysPath)) {
            console.log("🔑 Loading sender keys from saved file...");
            const keysData = JSON.parse(fs.readFileSync(keysPath, "utf8"));
            
            if (keysData.address === senderAddress) {
                console.log("✅ Sender keys loaded from file");
            } else {
                console.log("⚠️  Saved keys mismatch, generating new signature...");
                const message = `eERC
Registering user with
 Address:${senderAddress.toLowerCase()}`;
                signature = await wallet.signMessage(message);
            }
        } else {
            console.log("🔐 Generating signature for sender...");
            const message = `eERC
Registering user with
 Address:${senderAddress.toLowerCase()}`;
            signature = await wallet.signMessage(message);
        }
        
        // Create sender User object
        const sender = createUserFromSignature(signature, wallet);
        
        // Get public keys from registrar
        const senderPublicKey = await registrar.getUserPublicKey(senderAddress);
        const receiverPublicKey = await registrar.getUserPublicKey(receiverAddress);
        const auditorPublicKey = await encryptedERC.auditorPublicKey();
        
        console.log("🔑 Sender public key:", [senderPublicKey[0].toString(), senderPublicKey[1].toString()]);
        console.log("🔑 Receiver public key:", [receiverPublicKey[0].toString(), receiverPublicKey[1].toString()]);
        console.log("🔑 Auditor public key:", [auditorPublicKey.x.toString(), auditorPublicKey.y.toString()]);
        
        // Verify sender's keys match
        const derivedSenderPublicKey = sender.publicKey;
        const senderKeysMatch = derivedSenderPublicKey[0] === BigInt(senderPublicKey[0].toString()) && 
                               derivedSenderPublicKey[1] === BigInt(senderPublicKey[1].toString());
        
        if (!senderKeysMatch) {
            console.error("❌ Sender's private key doesn't match registered public key!");
            console.log("Run: npx hardhat run scripts/standalone/03_register-user.ts --network fuji");
            return;
        }
        console.log("✅ Sender keys verified");
        
        // For standalone mode, tokenId is always 0
        const tokenId = 0n;
        
        // Get sender's current encrypted balance
        console.log("🔍 Getting sender's encrypted balance...");
        const [eGCT, nonce, amountPCTs, balancePCT, transactionIndex] = await encryptedERC.balanceOf(senderAddress, tokenId);
        
        // Decrypt sender's balance using EGCT
        const c1: [bigint, bigint] = [BigInt(eGCT.c1.x.toString()), BigInt(eGCT.c1.y.toString())];
        const c2: [bigint, bigint] = [BigInt(eGCT.c2.x.toString()), BigInt(eGCT.c2.y.toString())];
        
        const isEGCTEmpty = c1[0] === 0n && c1[1] === 0n && c2[0] === 0n && c2[1] === 0n;
        if (isEGCTEmpty) {
            console.error("❌ Sender has no encrypted balance to transfer");
            return;
        }
        
        const senderCurrentBalance = decryptEGCTBalanceWithFormattedKey(sender.formattedPrivateKey, c1, c2);
        const tokenDecimals = await encryptedERC.decimals();
        
        console.log(`💰 Sender's current balance: ${ethers.formatUnits(senderCurrentBalance, tokenDecimals)} PRIV`);
        
        if (senderCurrentBalance < transferAmount) {
            console.error(`❌ Insufficient balance. Have: ${ethers.formatUnits(senderCurrentBalance, tokenDecimals)}, Need: ${ethers.formatUnits(transferAmount, tokenDecimals)}`);
            return;
        }
        
        console.log(`✅ Transfer amount: ${ethers.formatUnits(transferAmount, tokenDecimals)} PRIV tokens`);
        
        // Prepare data for transfer proof generation
        const senderEncryptedBalance = [c1[0], c1[1], c2[0], c2[1]];
        const receiverPublicKeyArray = [BigInt(receiverPublicKey[0].toString()), BigInt(receiverPublicKey[1].toString())];
        const auditorPublicKeyArray = [BigInt(auditorPublicKey.x.toString()), BigInt(auditorPublicKey.y.toString())];
        
        console.log("🔐 Generating transfer proof...");
        console.log("⏳ This may take a while...");
        
        // Generate transfer proof using the helper function
        const { proof, senderBalancePCT } = await privateTransfer(
            sender,
            senderCurrentBalance,
            receiverPublicKeyArray,
            transferAmount,
            senderEncryptedBalance,
            auditorPublicKeyArray
        );
        
        console.log("✅ Transfer proof generated successfully");
        
        // Debug the proof structure
        console.log("🔍 Debug: transfer proof structure:", proof);
        
        // Use the proof directly (since privateTransfer returns the correct calldata format)
        const transferProof = proof;
        
        console.log("📝 Submitting transfer to contract...");
        
        // Call the contract's transfer function
        const transferTx = await encryptedERC.transfer(
            receiverAddress,
            tokenId,
            transferProof,
            senderBalancePCT
        );
        
        console.log("📝 Transfer transaction sent:", transferTx.hash);
        
        const receipt = await transferTx.wait();
        console.log("✅ Transfer transaction confirmed in block:", receipt?.blockNumber);
        
        console.log("🎉 Private transfer completed successfully!");
        
        // Show updated balances
        console.log("\n🔍 Checking updated balances...");
        
        // Get sender's new balance
        const [newEGCT] = await encryptedERC.balanceOf(senderAddress, tokenId);
        const newC1: [bigint, bigint] = [BigInt(newEGCT.c1.x.toString()), BigInt(newEGCT.c1.y.toString())];
        const newC2: [bigint, bigint] = [BigInt(newEGCT.c2.x.toString()), BigInt(newEGCT.c2.y.toString())];
        const senderNewBalance = decryptEGCTBalanceWithFormattedKey(sender.formattedPrivateKey, newC1, newC2);
        
        console.log(`💰 Sender's new balance: ${ethers.formatUnits(senderNewBalance, tokenDecimals)} PRIV`);
        console.log(`📤 Amount transferred: ${ethers.formatUnits(transferAmount, tokenDecimals)} PRIV`);
        
        console.log("\n🎯 Transfer Summary:");
        console.log(`   From: ${senderAddress}`);
        console.log(`   To: ${receiverAddress}`);
        console.log(`   Amount: ${ethers.formatUnits(transferAmount, tokenDecimals)} PRIV tokens`);
        console.log(`   Transaction: ${transferTx.hash}`);
        console.log("\n💡 The receiver can check their balance using:");
        console.log("   npx hardhat run scripts/standalone/06_check-balance.ts --network fuji");
        
    } catch (error) {
        console.error("❌ Error during private transfer:");
        console.error(error);
        
        if (error instanceof Error) {
            if (error.message.includes("User not registered")) {
                console.error("💡 Hint: Both sender and receiver must be registered");
            } else if (error.message.includes("Auditor not set")) {
                console.error("💡 Hint: The auditor needs to be set in the EncryptedERC contract");
            } else if (error.message.includes("InvalidProof")) {
                console.error("💡 Hint: The transfer proof verification failed - check inputs");
            }
        }
        
        throw error;
    }
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});