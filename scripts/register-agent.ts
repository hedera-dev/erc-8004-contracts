import hre from "hardhat";

async function main() {
  // Hardhat exposes ethers v6 through hre.ethers
  const [deployer] = await hre.ethers.getSigners();
  console.log("Using deployer:", deployer.address);

  // Connect to your deployed IdentityRegistry
  const registryAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
  const registry = await hre.ethers.getContractAt("IdentityRegistry", registryAddress);

  // Call the register() function
  console.log("Registering agent...");
  const tx = await registry.connect(deployer).register("ipfs://example-agent.json");
  const receipt = await tx.wait();

  console.log("✅ Agent registered in tx:", receipt?.hash);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
