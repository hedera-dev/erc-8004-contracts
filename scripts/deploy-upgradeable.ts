import hre from "hardhat";
import { getCreate2Address, keccak256, encodeAbiParameters } from "viem";

/**
 * Deploy script for ERC-8004 upgradeable contracts using UUPS proxy pattern
 *
 * This script:
 * 1. Deploys implementation contracts for all three registries
 * 2. Deploys ERC1967Proxy for each implementation
 * 3. Initializes each proxy with appropriate parameters
 * 4. Returns proxy addresses for interaction
 */
async function main() {
  const { viem } = await hre.network.connect();
  const publicClient = await viem.getPublicClient();
  const [deployer] = await viem.getWalletClients();

  console.log("Deploying ERC-8004 Upgradeable Contracts");
  console.log("========================================");
  console.log("Deployer address:", deployer.account.address);
  console.log("");

  // Step 1: Deploy IdentityRegistry Implementation
  console.log("1. Deploying IdentityRegistry implementation...");
  const identityRegistryImpl = await viem.deployContract("IdentityRegistryUpgradeable");
  console.log("   Implementation deployed at:", identityRegistryImpl.address);

  // Step 2: Deploy IdentityRegistry Proxy
  console.log("2. Deploying IdentityRegistry proxy...");
  // initialize() function selector with no parameters
  const identityInitCalldata = "0x8129fc1c" as `0x${string}`;

  const identityProxy = await viem.deployContract("ERC1967Proxy", [
    identityRegistryImpl.address,
    identityInitCalldata
  ]);
  console.log("   Proxy deployed at:", identityProxy.address);
  console.log("");

  // Get IdentityRegistry instance through proxy
  const identityRegistry = await viem.getContractAt(
    "IdentityRegistryUpgradeable",
    identityProxy.address
  );

  // Step 3: Deploy ReputationRegistry Implementation
  console.log("3. Deploying ReputationRegistry implementation...");
  const reputationRegistryImpl = await viem.deployContract("ReputationRegistryUpgradeable");
  console.log("   Implementation deployed at:", reputationRegistryImpl.address);

  // Step 4: Deploy ReputationRegistry Proxy
  console.log("4. Deploying ReputationRegistry proxy...");
  // Encode the initialize(address) call
  const reputationInitCalldata = encodeAbiParameters(
    [{ name: "identityRegistry", type: "address" }],
    [identityProxy.address]
  );
  // Prepend function selector for initialize(address): 0xc4d66de8
  const reputationInitData = ("0xc4d66de8" + reputationInitCalldata.slice(2)) as `0x${string}`;

  const reputationProxy = await viem.deployContract("ERC1967Proxy", [
    reputationRegistryImpl.address,
    reputationInitData
  ]);
  console.log("   Proxy deployed at:", reputationProxy.address);
  console.log("");

  // Get ReputationRegistry instance through proxy
  const reputationRegistry = await viem.getContractAt(
    "ReputationRegistryUpgradeable",
    reputationProxy.address
  );

  // Step 5: Deploy ValidationRegistry Implementation
  console.log("5. Deploying ValidationRegistry implementation...");
  const validationRegistryImpl = await viem.deployContract("ValidationRegistryUpgradeable");
  console.log("   Implementation deployed at:", validationRegistryImpl.address);

  // Step 6: Deploy ValidationRegistry Proxy
  console.log("6. Deploying ValidationRegistry proxy...");
  // Encode the initialize(address) call
  const validationInitCalldata = encodeAbiParameters(
    [{ name: "identityRegistry", type: "address" }],
    [identityProxy.address]
  );
  // Prepend function selector for initialize(address): 0xc4d66de8
  const validationInitData = ("0xc4d66de8" + validationInitCalldata.slice(2)) as `0x${string}`;

  const validationProxy = await viem.deployContract("ERC1967Proxy", [
    validationRegistryImpl.address,
    validationInitData
  ]);
  console.log("   Proxy deployed at:", validationProxy.address);
  console.log("");

  // Get ValidationRegistry instance through proxy
  const validationRegistry = await viem.getContractAt(
    "ValidationRegistryUpgradeable",
    validationProxy.address
  );

  // Verify deployments
  console.log("Verifying deployments...");
  console.log("=========================");

  const identityVersion = await identityRegistry.read.getVersion();
  console.log("IdentityRegistry version:", identityVersion);

  const reputationVersion = await reputationRegistry.read.getVersion();
  const reputationIdentityRegistry = await reputationRegistry.read.getIdentityRegistry();
  console.log("ReputationRegistry version:", reputationVersion);
  console.log("ReputationRegistry identityRegistry:", reputationIdentityRegistry);

  const validationVersion = await validationRegistry.read.getVersion();
  const validationIdentityRegistry = await validationRegistry.read.getIdentityRegistry();
  console.log("ValidationRegistry version:", validationVersion);
  console.log("ValidationRegistry identityRegistry:", validationIdentityRegistry);
  console.log("");

  // Summary
  console.log("Deployment Summary");
  console.log("==================");
  console.log("IdentityRegistry Proxy:", identityProxy.address);
  console.log("ReputationRegistry Proxy:", reputationProxy.address);
  console.log("ValidationRegistry Proxy:", validationProxy.address);
  console.log("");
  console.log("Implementation Addresses:");
  console.log("IdentityRegistry Implementation:", identityRegistryImpl.address);
  console.log("ReputationRegistry Implementation:", reputationRegistryImpl.address);
  console.log("ValidationRegistry Implementation:", validationRegistryImpl.address);
  console.log("");
  console.log("✅ All contracts deployed successfully!");

  return {
    proxies: {
      identityRegistry: identityProxy.address,
      reputationRegistry: reputationProxy.address,
      validationRegistry: validationProxy.address
    },
    implementations: {
      identityRegistry: identityRegistryImpl.address,
      reputationRegistry: reputationRegistryImpl.address,
      validationRegistry: validationRegistryImpl.address
    }
  };
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
