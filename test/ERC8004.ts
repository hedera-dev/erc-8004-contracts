import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { encodeAbiParameters, getAddress, keccak256, toHex } from "viem";

describe("ERC8004 Registries", async function () {
  const { viem } = await network.connect();
  const publicClient = await viem.getPublicClient();

  // Helper function to extract agentId from Registered event
  async function getAgentIdFromRegistration(txHash: `0x${string}`) {
    const receipt = await publicClient.getTransactionReceipt({ hash: txHash });
    const registeredLog = receipt.logs.find(log => log.topics[0] === keccak256(toHex("Registered(uint256,string,address)")));
    if (!registeredLog || !registeredLog.topics[1]) {
      throw new Error("Registered event not found");
    }
    return BigInt(registeredLog.topics[1]);
  }

  // Helper function to create signed feedbackAuth
  async function createFeedbackAuth(
    agentId: bigint,
    clientAddress: `0x${string}`,
    identityRegistryAddress: `0x${string}`,
    signer: any
  ) {
    const chainId = BigInt(await publicClient.getChainId());
    const indexLimit = 100n; // Allow up to 100 feedback submissions
    const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour from now

    // Construct message to sign (using encodeAbiParameters to match contract's abi.encode)
    const messageHash = keccak256(
      encodeAbiParameters(
        [
          { type: "uint256" },
          { type: "address" },
          { type: "uint64" },
          { type: "uint256" },
          { type: "uint256" },
          { type: "address" },
          { type: "address" }
        ],
        [agentId, clientAddress, indexLimit, expiry, chainId, identityRegistryAddress, signer.account.address]
      )
    );

    // Sign with signer's private key (EIP-191)
    const signature = await signer.signMessage({
      message: { raw: messageHash }
    });

    // Construct feedbackAuth
    const feedbackAuthEncoded = encodeAbiParameters(
      [
        { type: "uint256" },
        { type: "address" },
        { type: "uint64" },
        { type: "uint256" },
        { type: "uint256" },
        { type: "address" },
        { type: "address" }
      ],
      [agentId, clientAddress, indexLimit, expiry, chainId, identityRegistryAddress, signer.account.address]
    );

    // Concatenate the signature at the end
    return (feedbackAuthEncoded + signature.slice(2)) as `0x${string}`;
  }

  describe("IdentityRegistry", async function () {
    it("Should register an agent with tokenURI", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const [owner] = await viem.getWalletClients();

      const tokenURI = "ipfs://QmTest123";
      const txHash = await identityRegistry.write.register([tokenURI]);
      const agentId = await getAgentIdFromRegistration(txHash);

      // Verify tokenURI was set
      const retrievedURI = await identityRegistry.read.tokenURI([agentId]);
      assert.equal(retrievedURI, tokenURI);

      // Verify owner
      const tokenOwner = await identityRegistry.read.ownerOf([agentId]);
      assert.equal(tokenOwner.toLowerCase(), owner.account.address.toLowerCase());
    });

    it("Should auto-increment agentId", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");

      const txHash1 = await identityRegistry.write.register(["ipfs://agent1"]);
      const txHash2 = await identityRegistry.write.register(["ipfs://agent2"]);
      const txHash3 = await identityRegistry.write.register(["ipfs://agent3"]);

      const agentId1 = await getAgentIdFromRegistration(txHash1);
      const agentId2 = await getAgentIdFromRegistration(txHash2);
      const agentId3 = await getAgentIdFromRegistration(txHash3);

      const uri1 = await identityRegistry.read.tokenURI([agentId1]);
      const uri2 = await identityRegistry.read.tokenURI([agentId2]);
      const uri3 = await identityRegistry.read.tokenURI([agentId3]);

      assert.equal(uri1, "ipfs://agent1");
      assert.equal(uri2, "ipfs://agent2");
      assert.equal(uri3, "ipfs://agent3");

      // Verify auto-increment
      assert.equal(agentId2, agentId1 + 1n);
      assert.equal(agentId3, agentId2 + 1n);
    });

    /**
     * "The tokenURI MUST resolve to the agent registration file. It MAY use any URI scheme such as ipfs://
     * (e.g., ipfs://cid) or https:// (e.g., https://domain.com/agent3.json). When the registration data
     * changes, it can be updated with _setTokenURI() as per ERC721URIStorage."
     */
    it("Should allow owner to update tokenURI", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const [owner] = await viem.getWalletClients();

      // Register with initial URI
      const txHash = await identityRegistry.write.register(["ipfs://initialUri"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      // Verify initial URI
      const initialUri = await identityRegistry.read.tokenURI([agentId]);
      assert.equal(initialUri, "ipfs://initialUri");

      // Update tokenURI
      const newUri = "https://example.com/updated-agent.json";
      await identityRegistry.write.setAgentUri([agentId, newUri]);

      // Verify updated URI
      const updatedUri = await identityRegistry.read.tokenURI([agentId]);
      assert.equal(updatedUri, newUri);
    });

    /**
     * "The tokenURI MUST resolve to the agent registration file. It MAY use any URI scheme such as ipfs://
     * (e.g., ipfs://cid) or https:// (e.g., https://domain.com/agent3.json)."
     */
    it("Should support different URI schemes for tokenURI", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");

      // Test ipfs://
      const txHash1 = await identityRegistry.write.register(["ipfs://QmTestCID123"]);
      const agentId1 = await getAgentIdFromRegistration(txHash1);
      const ipfsUri = await identityRegistry.read.tokenURI([agentId1]);
      assert.equal(ipfsUri, "ipfs://QmTestCID123");

      // Test https://
      const txHash2 = await identityRegistry.write.register(["https://domain.com/agent3.json"]);
      const agentId2 = await getAgentIdFromRegistration(txHash2);
      const httpsUri = await identityRegistry.read.tokenURI([agentId2]);
      assert.equal(httpsUri, "https://domain.com/agent3.json");

      // Test http:// (should work even though spec upgrades to https)
      const txHash3 = await identityRegistry.write.register(["http://example.com/agent.json"]);
      const agentId3 = await getAgentIdFromRegistration(txHash3);
      const httpUri = await identityRegistry.read.tokenURI([agentId3]);
      assert.equal(httpUri, "http://example.com/agent.json");
    });

    it("Should set and get metadata", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const [owner] = await viem.getWalletClients();

      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const key = "agentWallet";
      const value = toHex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7");

      // Set metadata
      await viem.assertions.emitWithArgs(
        identityRegistry.write.setMetadata([agentId, key, value]),
        identityRegistry,
        "MetadataSet",
        [agentId, keccak256(toHex(key)), key, value]
      );

      // Get metadata
      const retrieved = await identityRegistry.read.getMetadata([agentId, key]);
      assert.equal(retrieved, value);
    });

    it("Should only allow owner to set metadata", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const [owner, attacker] = await viem.getWalletClients();

      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      // Try to set metadata as non-owner
      await assert.rejects(
        identityRegistry.write.setMetadata(
          [agentId, "key", toHex("value")],
          { account: attacker.account }
        )
      );
    });

    it("Should register with metadata array", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const [owner] = await viem.getWalletClients();

      const tokenURI = "ipfs://agent-with-metadata";
      const metadata = [
        { key: "agentWallet", value: toHex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7") },
        { key: "agentName", value: toHex("MyAgent") }
      ];

      const txHash = await identityRegistry.write.register([tokenURI, metadata]);
      const agentId = await getAgentIdFromRegistration(txHash);

      // Verify metadata was set
      const wallet = await identityRegistry.read.getMetadata([agentId, "agentWallet"]);
      const name = await identityRegistry.read.getMetadata([agentId, "agentName"]);

      assert.equal(wallet, metadata[0].value);
      assert.equal(name, metadata[1].value);
    });

    /**
     * "function register() returns (uint256 agentId)
     * // tokenURI is added later with _setTokenURI()"
     */
    it("Should register without tokenURI and set it later", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const [owner] = await viem.getWalletClients();

      // Register without tokenURI
      const txHash = await identityRegistry.write.register();
      const agentId = await getAgentIdFromRegistration(txHash);

      // Verify owner
      const tokenOwner = await identityRegistry.read.ownerOf([agentId]);
      assert.equal(tokenOwner.toLowerCase(), owner.account.address.toLowerCase());

      // tokenURI should be empty initially
      const initialUri = await identityRegistry.read.tokenURI([agentId]);
      assert.equal(initialUri, "");

      // Set tokenURI later
      await identityRegistry.write.setAgentUri([agentId, "ipfs://later-set-uri"]);
      const updatedUri = await identityRegistry.read.tokenURI([agentId]);
      assert.equal(updatedUri, "ipfs://later-set-uri");
    });
  });

  describe("ReputationRegistry", async function () {
    /**
     * "When the Reputation Registry is deployed, the identityRegistry address is passed to the constructor and publicly visible by calling:
     * function getIdentityRegistry() external view returns (address identityRegistry)"
     */
    it("Should return the identity registry address", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const retrievedAddress = await reputationRegistry.read.getIdentityRegistry();
      assert.equal(retrievedAddress.toLowerCase(), identityRegistry.address.toLowerCase());
    });

    it("Should give feedback to an agent", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
      const agentId = await getAgentIdFromRegistration(txHash);

      const score = 85;
      const tag1 = keccak256(toHex("quality"));
      const tag2 = keccak256(toHex("speed"));
      const fileuri = "ipfs://feedback1";
      const filehash = keccak256(toHex("feedback content"));

      // Create signed feedbackAuth
      const feedbackAuth = await createFeedbackAuth(
        agentId,
        client.account.address,
        identityRegistry.address,
        agentOwner
      );

      await viem.assertions.emitWithArgs(
        reputationRegistry.write.giveFeedback([
          agentId,
          score,
          tag1,
          tag2,
          fileuri,
          filehash,
          feedbackAuth,
        ], { account: client.account }),
        reputationRegistry,
        "NewFeedback",
        [agentId, getAddress(client.account.address), score, tag1, tag2, fileuri, filehash]
      );

      // Read feedback back (use 1-based index)
      const feedback = await reputationRegistry.read.readFeedback([
        agentId,
        client.account.address,
        1n,
      ]);

      assert.equal(feedback[0], score); // score
      assert.equal(feedback[1], tag1); // tag1
      assert.equal(feedback[2], tag2); // tag2
      assert.equal(feedback[3], false); // isRevoked
    });

    it("Should revoke feedback", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
      const agentId = await getAgentIdFromRegistration(txHash);

      const feedbackAuth = await createFeedbackAuth(agentId, client.account.address, identityRegistry.address, agentOwner);

      await reputationRegistry.write.giveFeedback([
        agentId,
        90,
        keccak256(toHex("tag1")),
        keccak256(toHex("tag2")),
        "ipfs://feedback",
        keccak256(toHex("content")),
        feedbackAuth,
      ], { account: client.account });

      // Revoke feedback (use 1-based index) - must be called by the client who gave feedback
      await viem.assertions.emitWithArgs(
        reputationRegistry.write.revokeFeedback([agentId, 1n], { account: client.account }),
        reputationRegistry,
        "FeedbackRevoked",
        [agentId, getAddress(client.account.address), 1n]
      );

      // Verify feedback is revoked
      const feedback = await reputationRegistry.read.readFeedback([
        agentId,
        client.account.address,
        1n,
      ]);
      assert.equal(feedback[3], true); // isRevoked
    });

    it("Should append response to feedback", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client, responder] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
      const agentId = await getAgentIdFromRegistration(txHash);

      const feedbackAuth = await createFeedbackAuth(agentId, client.account.address, identityRegistry.address, agentOwner);

      await reputationRegistry.write.giveFeedback([
        agentId,
        75,
        keccak256(toHex("tag1")),
        keccak256(toHex("tag2")),
        "ipfs://feedback",
        keccak256(toHex("content")),
        feedbackAuth,
      ], { account: client.account });

      const responseUri = "ipfs://response1";
      const responseHash = keccak256(toHex("response content"));

      await viem.assertions.emitWithArgs(
        reputationRegistry.write.appendResponse(
          [agentId, client.account.address, 1n, responseUri, responseHash],
          { account: responder.account }
        ),
        reputationRegistry,
        "ResponseAppended",
        [agentId, getAddress(client.account.address), 1n, getAddress(responder.account.address), responseUri, responseHash]
      );
    });

    it("Should track multiple feedbacks from same client", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
      const agentId = await getAgentIdFromRegistration(txHash);

      const feedbackAuth = await createFeedbackAuth(agentId, client.account.address, identityRegistry.address, agentOwner);

      // Give 3 feedbacks
      for (let i = 0; i < 3; i++) {
        await reputationRegistry.write.giveFeedback([
          agentId,
          80 + i,
          keccak256(toHex("tag1")),
          keccak256(toHex("tag2")),
          `ipfs://feedback${i}`,
          keccak256(toHex(`content${i}`)),
          feedbackAuth,
        ], { account: client.account });
      }

      const lastIndex = await reputationRegistry.read.getLastIndex([
        agentId,
        client.account.address,
      ]);
      assert.equal(lastIndex, 3n); // length = 3 (1-based indices: 1, 2, 3)

      // Read all feedbacks (use 1-based indices)
      const fb0 = await reputationRegistry.read.readFeedback([agentId, client.account.address, 1n]);
      const fb1 = await reputationRegistry.read.readFeedback([agentId, client.account.address, 2n]);
      const fb2 = await reputationRegistry.read.readFeedback([agentId, client.account.address, 3n]);

      assert.equal(fb0[0], 80);
      assert.equal(fb1[0], 81);
      assert.equal(fb2[0], 82);
    });

    /**
     * "The agentId must be a validly registered agent. The score MUST be between 0 and 100."
     */
    it("Should reject feedback for non-existent agent", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      // Don't register any agent, try to give feedback to agentId 999
      await assert.rejects(
        reputationRegistry.write.giveFeedback([
          999n,
          85,
          keccak256(toHex("tag1")),
          keccak256(toHex("tag2")),
          "ipfs://feedback",
          keccak256(toHex("content")),
          "0x",
        ])
      );
    });

    /**
     * "The score MUST be between 0 and 100."
     */
    it("Should reject score > 100", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      await identityRegistry.write.register(["ipfs://agent"]);

      await assert.rejects(
        reputationRegistry.write.giveFeedback([
          0n,
          101,
          keccak256(toHex("tag1")),
          keccak256(toHex("tag2")),
          "ipfs://feedback",
          keccak256(toHex("content")),
          "0x",
        ])
      );
    });

    /**
     * "The score MUST be between 0 and 100."
     */
    it("Should accept score of 0", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
      const agentId = await getAgentIdFromRegistration(txHash);

      const feedbackAuth = await createFeedbackAuth(agentId, client.account.address, identityRegistry.address, agentOwner);

      // Score of 0 should be valid
      await reputationRegistry.write.giveFeedback([
        agentId,
        0,
        keccak256(toHex("tag1")),
        keccak256(toHex("tag2")),
        "ipfs://feedback",
        keccak256(toHex("content")),
        feedbackAuth,
      ], { account: client.account });

      const feedback = await reputationRegistry.read.readFeedback([agentId, client.account.address, 1n]);
      assert.equal(feedback[0], 0);
    });

    /**
     * "The score MUST be between 0 and 100."
     */
    it("Should accept score of 100", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
      const agentId = await getAgentIdFromRegistration(txHash);

      const feedbackAuth = await createFeedbackAuth(agentId, client.account.address, identityRegistry.address, agentOwner);

      // Score of 100 should be valid
      await reputationRegistry.write.giveFeedback([
        agentId,
        100,
        keccak256(toHex("tag1")),
        keccak256(toHex("tag2")),
        "ipfs://feedback",
        keccak256(toHex("content")),
        feedbackAuth,
      ], { account: client.account });

      const feedback = await reputationRegistry.read.readFeedback([agentId, client.account.address, 1n]);
      assert.equal(feedback[0], 100);
    });

    it("Should reject feedback without auth (empty bytes)", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      await identityRegistry.write.register(["ipfs://agent"]);

      // Empty auth should be REJECTED (feedbackAuth is mandatory)
      await assert.rejects(
        async () => {
          await reputationRegistry.write.giveFeedback([
            1n,
            95,
            keccak256(toHex("tag1")),
            keccak256(toHex("tag2")),
            "ipfs://feedback",
            keccak256(toHex("content")),
            "0x",
          ]);
        },
        /Invalid auth data length|revert/
      );
    });

    it("Should calculate summary with average score", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client1, client2] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
      const agentId = await getAgentIdFromRegistration(txHash);

      const tag1 = keccak256(toHex("service"));
      const tag2 = keccak256(toHex("fast"));

      const feedbackAuth1 = await createFeedbackAuth(agentId, client1.account.address, identityRegistry.address, agentOwner);
      const feedbackAuth2 = await createFeedbackAuth(agentId, client2.account.address, identityRegistry.address, agentOwner);

      // Client 1 gives 2 feedbacks
      await reputationRegistry.write.giveFeedback([
        agentId, 80, tag1, tag2, "ipfs://f1", keccak256(toHex("c1")), feedbackAuth1
      ], { account: client1.account });
      await reputationRegistry.write.giveFeedback([
        agentId, 90, tag1, tag2, "ipfs://f2", keccak256(toHex("c2")), feedbackAuth1
      ], { account: client1.account });

      // Client 2 gives 1 feedback
      await reputationRegistry.write.giveFeedback(
        [agentId, 100, tag1, tag2, "ipfs://f3", keccak256(toHex("c3")), feedbackAuth2],
        { account: client2.account }
      );

      // Get summary for both clients
      const summary = await reputationRegistry.read.getSummary([
        agentId,
        [client1.account.address, client2.account.address],
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000"
      ]);

      assert.equal(summary[0], 3n); // count = 3
      assert.equal(summary[1], 90); // average = (80 + 90 + 100) / 3 = 90
    });

    it("Should filter summary by tags", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
      const agentId = await getAgentIdFromRegistration(txHash);

      const tagA = keccak256(toHex("tagA"));
      const tagB = keccak256(toHex("tagB"));
      const tagC = keccak256(toHex("tagC"));

      const feedbackAuth = await createFeedbackAuth(agentId, client.account.address, identityRegistry.address, agentOwner);

      // Give feedbacks with different tags
      await reputationRegistry.write.giveFeedback([agentId, 80, tagA, tagB, "", "0x0000000000000000000000000000000000000000000000000000000000000000", feedbackAuth], { account: client.account });
      await reputationRegistry.write.giveFeedback([agentId, 90, tagA, tagC, "", "0x0000000000000000000000000000000000000000000000000000000000000000", feedbackAuth], { account: client.account });
      await reputationRegistry.write.giveFeedback([agentId, 100, tagB, tagC, "", "0x0000000000000000000000000000000000000000000000000000000000000000", feedbackAuth], { account: client.account });

      // Filter by tagA
      const summaryA = await reputationRegistry.read.getSummary([agentId, [client.account.address], tagA, "0x0000000000000000000000000000000000000000000000000000000000000000"]);
      assert.equal(summaryA[0], 2n); // count = 2 (first two)
      assert.equal(summaryA[1], 85); // average = (80 + 90) / 2 = 85
    });

    it("Should read all feedback with filters", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client1, client2] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
      const agentId = await getAgentIdFromRegistration(txHash);

      const tag1 = keccak256(toHex("quality"));

      const feedbackAuth1 = await createFeedbackAuth(agentId, client1.account.address, identityRegistry.address, agentOwner);
      const feedbackAuth2 = await createFeedbackAuth(agentId, client2.account.address, identityRegistry.address, agentOwner);

      // Client1: 2 feedbacks
      await reputationRegistry.write.giveFeedback([agentId, 80, tag1, "0x0000000000000000000000000000000000000000000000000000000000000000", "", "0x0000000000000000000000000000000000000000000000000000000000000000", feedbackAuth1], { account: client1.account });
      await reputationRegistry.write.giveFeedback([agentId, 90, tag1, "0x0000000000000000000000000000000000000000000000000000000000000000", "", "0x0000000000000000000000000000000000000000000000000000000000000000", feedbackAuth1], { account: client1.account });

      // Client2: 1 feedback
      await reputationRegistry.write.giveFeedback(
        [agentId, 100, tag1, "0x0000000000000000000000000000000000000000000000000000000000000000", "", "0x0000000000000000000000000000000000000000000000000000000000000000", feedbackAuth2],
        { account: client2.account }
      );

      // Read all feedback
      const result = await reputationRegistry.read.readAllFeedback([
        agentId,
        [client1.account.address, client2.account.address],
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        false // don't include revoked
      ]);

      assert.equal(result[1].length, 3); // 3 feedbacks
      assert.equal(result[1][0], 80);
      assert.equal(result[1][1], 90);
      assert.equal(result[1][2], 100);
    });

    it("Should store responses and count them", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client, responder1, responder2] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
      const agentId = await getAgentIdFromRegistration(txHash);

      const feedbackAuth = await createFeedbackAuth(agentId, client.account.address, identityRegistry.address, agentOwner);

      // Give feedback
      await reputationRegistry.write.giveFeedback([
        agentId, 85, "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000", "", "0x0000000000000000000000000000000000000000000000000000000000000000", feedbackAuth
      ], { account: client.account });

      // Append 2 responses from different responders (use 1-based index)
      await reputationRegistry.write.appendResponse(
        [agentId, client.account.address, 1n, "ipfs://response1", "0x0000000000000000000000000000000000000000000000000000000000000000"],
        { account: responder1.account }
      );
      await reputationRegistry.write.appendResponse(
        [agentId, client.account.address, 1n, "ipfs://response2", "0x0000000000000000000000000000000000000000000000000000000000000000"],
        { account: responder2.account }
      );

      // Get response count (with responder filter - required for counter-only model)
      const totalCount = await reputationRegistry.read.getResponseCount([
        agentId, client.account.address, 1n, [responder1.account.address, responder2.account.address]
      ]);
      assert.equal(totalCount, 2n);

      // Get response count (filter by responder1)
      const responder1Count = await reputationRegistry.read.getResponseCount([
        agentId, client.account.address, 1n, [responder1.account.address]
      ]);
      assert.equal(responder1Count, 1n);
    });

    /**
     * "function getClients(uint256 agentId) external view returns (address[] memory)"
     */
    it("Should return list of clients who gave feedback", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client1, client2, client3] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
      const agentId = await getAgentIdFromRegistration(txHash);

      const feedbackAuth1 = await createFeedbackAuth(agentId, client1.account.address, identityRegistry.address, agentOwner);
      const feedbackAuth2 = await createFeedbackAuth(agentId, client2.account.address, identityRegistry.address, agentOwner);
      const feedbackAuth3 = await createFeedbackAuth(agentId, client3.account.address, identityRegistry.address, agentOwner);

      // Client1 gives feedback
      await reputationRegistry.write.giveFeedback([
        agentId, 80, "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000", "", "0x0000000000000000000000000000000000000000000000000000000000000000", feedbackAuth1
      ], { account: client1.account });

      // Client2 gives feedback
      await reputationRegistry.write.giveFeedback(
        [agentId, 90, "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000", "", "0x0000000000000000000000000000000000000000000000000000000000000000", feedbackAuth2],
        { account: client2.account }
      );

      // Client3 gives feedback
      await reputationRegistry.write.giveFeedback(
        [agentId, 95, "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000", "", "0x0000000000000000000000000000000000000000000000000000000000000000", feedbackAuth3],
        { account: client3.account }
      );

      // Get all clients
      const clients = await reputationRegistry.read.getClients([agentId]);
      assert.equal(clients.length, 3);

      // Verify all clients are in the list
      const clientAddresses = clients.map(addr => addr.toLowerCase());
      assert.ok(clientAddresses.includes(client1.account.address.toLowerCase()));
      assert.ok(clientAddresses.includes(client2.account.address.toLowerCase()));
      assert.ok(clientAddresses.includes(client3.account.address.toLowerCase()));
    });

    it("Should verify feedbackAuth signature from agent owner", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client] = await viem.getWalletClients();

      // Register agent (owner is agentOwner)
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      // Prepare feedbackAuth parameters
      const chainId = BigInt(await publicClient.getChainId());
      const indexLimit = 10n;
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour from now

      // Construct message to sign (using encodeAbiParameters to match contract's abi.encode)
      const messageHash = keccak256(
        encodeAbiParameters(
          [
            { type: "uint256" },
            { type: "address" },
            { type: "uint64" },
            { type: "uint256" },
            { type: "uint256" },
            { type: "address" },
            { type: "address" }
          ],
          [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, agentOwner.account.address]
        )
      );

      // Sign with agent owner's private key (EIP-191)
      const signature = await agentOwner.signMessage({
        message: { raw: messageHash }
      });

      // Construct feedbackAuth: (agentId, clientAddress, indexLimit, expiry, chainId, identityRegistry, signerAddress, signature)
      // Note: signature is already a bytes value, so we encode it as bytes without re-encoding
      const feedbackAuthEncoded = encodeAbiParameters(
        [
          { type: "uint256" },
          { type: "address" },
          { type: "uint64" },
          { type: "uint256" },
          { type: "uint256" },
          { type: "address" },
          { type: "address" }
        ],
        [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, agentOwner.account.address]
      );
      // Concatenate the signature at the end
      const feedbackAuth = (feedbackAuthEncoded + signature.slice(2)) as `0x${string}`;

      // Give feedback with valid auth (as client)
      await reputationRegistry.write.giveFeedback(
        [
          agentId,
          95,
          keccak256(toHex("quality")),
          keccak256(toHex("service")),
          "ipfs://feedback",
          keccak256(toHex("content")),
          feedbackAuth
        ],
        { account: client.account }
      );

      // Verify feedback was recorded
      const feedback = await reputationRegistry.read.readFeedback([agentId, client.account.address, 1n]);
      assert.equal(feedback[0], 95);
    });

    it("Should reject feedbackAuth with invalid signature", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client, attacker] = await viem.getWalletClients();

      // Register agent (owner is agentOwner)
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const chainId = BigInt(await publicClient.getChainId());
      const indexLimit = 10n;
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

      // Construct message
      const messageHash = keccak256(
        encodeAbiParameters(
          [
            { type: "uint256" },
            { type: "address" },
            { type: "uint64" },
            { type: "uint256" },
            { type: "uint256" },
            { type: "address" },
            { type: "address" }
          ],
          [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, agentOwner.account.address]
        )
      );

      // Sign with ATTACKER's key (not the owner)
      const badSignature = await attacker.signMessage({
        message: { raw: messageHash }
      });

      // Construct feedbackAuth with bad signature
      const feedbackAuthEncoded = encodeAbiParameters(
        [
          { type: "uint256" },
          { type: "address" },
          { type: "uint64" },
          { type: "uint256" },
          { type: "uint256" },
          { type: "address" },
          { type: "address" }
        ],
        [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, agentOwner.account.address]
      );
      const feedbackAuth = (feedbackAuthEncoded + badSignature.slice(2)) as `0x${string}`;

      // Should reject
      await assert.rejects(
        reputationRegistry.write.giveFeedback(
          [
            agentId,
            95,
            keccak256(toHex("quality")),
            keccak256(toHex("service")),
            "ipfs://feedback",
            keccak256(toHex("content")),
            feedbackAuth
          ],
          { account: client.account }
        )
      );
    });

    it("Should reject feedbackAuth signed by non-owner/non-operator", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client, attacker] = await viem.getWalletClients();

      // Register agent (owner is agentOwner)
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const chainId = BigInt(await publicClient.getChainId());
      const indexLimit = 10n;
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

      // Construct message claiming attacker is the signer
      const messageHash = keccak256(
        encodeAbiParameters(
          [
            { type: "uint256" },
            { type: "address" },
            { type: "uint64" },
            { type: "uint256" },
            { type: "uint256" },
            { type: "address" },
            { type: "address" }
          ],
          [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, attacker.account.address]
        )
      );

      // Attacker signs correctly (signature is valid)
      const signature = await attacker.signMessage({
        message: { raw: messageHash }
      });

      // Construct feedbackAuth
      const feedbackAuthEncoded = encodeAbiParameters(
        [
          { type: "uint256" },
          { type: "address" },
          { type: "uint64" },
          { type: "uint256" },
          { type: "uint256" },
          { type: "address" },
          { type: "address" }
        ],
        [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, attacker.account.address]
      );
      const feedbackAuth = (feedbackAuthEncoded + signature.slice(2)) as `0x${string}`;

      // Should reject because attacker is not owner/operator
      await assert.rejects(
        reputationRegistry.write.giveFeedback(
          [
            agentId,
            95,
            keccak256(toHex("quality")),
            keccak256(toHex("service")),
            "ipfs://feedback",
            keccak256(toHex("content")),
            feedbackAuth
          ],
          { account: client.account }
        )
      );
    });

    it("Should accept feedbackAuth from approved operator", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client, operator] = await viem.getWalletClients();

      // Register agent
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      // Owner approves operator
      await identityRegistry.write.setApprovalForAll([operator.account.address, true]);

      const chainId = BigInt(await publicClient.getChainId());
      const indexLimit = 10n;
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

      // Operator signs the feedbackAuth
      const messageHash = keccak256(
        encodeAbiParameters(
          [
            { type: "uint256" },
            { type: "address" },
            { type: "uint64" },
            { type: "uint256" },
            { type: "uint256" },
            { type: "address" },
            { type: "address" }
          ],
          [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, operator.account.address]
        )
      );

      const signature = await operator.signMessage({
        message: { raw: messageHash }
      });

      const feedbackAuthEncoded = encodeAbiParameters(
        [
          { type: "uint256" },
          { type: "address" },
          { type: "uint64" },
          { type: "uint256" },
          { type: "uint256" },
          { type: "address" },
          { type: "address" }
        ],
        [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, operator.account.address]
      );
      const feedbackAuth = (feedbackAuthEncoded + signature.slice(2)) as `0x${string}`;

      // Should succeed because operator is approved
      await reputationRegistry.write.giveFeedback(
        [
          agentId,
          88,
          keccak256(toHex("quality")),
          keccak256(toHex("service")),
          "ipfs://feedback",
          keccak256(toHex("content")),
          feedbackAuth
        ],
        { account: client.account }
      );

      const feedback = await reputationRegistry.read.readFeedback([agentId, client.account.address, 1n]);
      assert.equal(feedback[0], 88);
    });

    it("Should reject expired feedbackAuth", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client] = await viem.getWalletClients();

      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const chainId = BigInt(await publicClient.getChainId());
      const indexLimit = 10n;
      const expiry = BigInt(Math.floor(Date.now() / 1000) - 3600); // 1 hour ago (expired)

      const messageHash = keccak256(
        encodeAbiParameters(
          [
            { type: "uint256" },
            { type: "address" },
            { type: "uint64" },
            { type: "uint256" },
            { type: "uint256" },
            { type: "address" },
            { type: "address" }
          ],
          [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, agentOwner.account.address]
        )
      );

      const signature = await agentOwner.signMessage({
        message: { raw: messageHash }
      });

      const feedbackAuthEncoded = encodeAbiParameters(
        [
          { type: "uint256" },
          { type: "address" },
          { type: "uint64" },
          { type: "uint256" },
          { type: "uint256" },
          { type: "address" },
          { type: "address" }
        ],
        [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, agentOwner.account.address]
      );
      const feedbackAuth = (feedbackAuthEncoded + signature.slice(2)) as `0x${string}`;

      // Should reject expired auth
      await assert.rejects(
        reputationRegistry.write.giveFeedback(
          [
            agentId,
            95,
            keccak256(toHex("quality")),
            keccak256(toHex("service")),
            "ipfs://feedback",
            keccak256(toHex("content")),
            feedbackAuth
          ],
          { account: client.account }
        )
      );
    });

    it("Should reject feedbackAuth with exceeded indexLimit", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client] = await viem.getWalletClients();

      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const chainId = BigInt(await publicClient.getChainId());
      const indexLimit = 1n; // Only allow 1 feedback
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

      const messageHash = keccak256(
        encodeAbiParameters(
          [
            { type: "uint256" },
            { type: "address" },
            { type: "uint64" },
            { type: "uint256" },
            { type: "uint256" },
            { type: "address" },
            { type: "address" }
          ],
          [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, agentOwner.account.address]
        )
      );

      const signature = await agentOwner.signMessage({
        message: { raw: messageHash }
      });

      const feedbackAuthEncoded = encodeAbiParameters(
        [
          { type: "uint256" },
          { type: "address" },
          { type: "uint64" },
          { type: "uint256" },
          { type: "uint256" },
          { type: "address" },
          { type: "address" }
        ],
        [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, agentOwner.account.address]
      );
      const feedbackAuth = (feedbackAuthEncoded + signature.slice(2)) as `0x${string}`;

      // First feedback succeeds
      await reputationRegistry.write.giveFeedback(
        [
          agentId,
          95,
          keccak256(toHex("quality")),
          keccak256(toHex("service")),
          "ipfs://feedback1",
          keccak256(toHex("content1")),
          feedbackAuth
        ],
        { account: client.account }
      );

      // Second feedback with same auth should fail (indexLimit exceeded)
      await assert.rejects(
        reputationRegistry.write.giveFeedback(
          [
            agentId,
            90,
            keccak256(toHex("quality")),
            keccak256(toHex("service")),
            "ipfs://feedback2",
            keccak256(toHex("content2")),
            feedbackAuth
          ],
          { account: client.account }
        )
      );
    });

    /**
     * EIP-1271 Smart Contract Wallet Tests
     * "signed using EIP-191 or ERC-1271 (if clientAddress is a smart contract)"
     */
    describe("EIP-1271 Support", async function () {
      it("Should accept feedbackAuth signed by ERC-1271 smart contract wallet", async function () {
        const identityRegistry = await viem.deployContract("IdentityRegistry");
        const reputationRegistry = await viem.deployContract("ReputationRegistry", [
          identityRegistry.address,
        ]);

        const [agentOwner, walletOwner, client] = await viem.getWalletClients();

        // Deploy agent with agentOwner
        const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
        const agentId = await getAgentIdFromRegistration(txHash);

        // Deploy ERC-1271 wallet owned by walletOwner
        const erc1271Wallet = await viem.deployContract("MockERC1271Wallet", [walletOwner.account.address]);

        // Transfer agent ownership to the smart contract wallet
        await identityRegistry.write.transferFrom(
          [agentOwner.account.address, erc1271Wallet.address, agentId],
          { account: agentOwner.account }
        );

        // Verify wallet now owns the agent
        const newOwner = await identityRegistry.read.ownerOf([agentId]);
        assert.equal(newOwner.toLowerCase(), erc1271Wallet.address.toLowerCase());

        // Prepare feedbackAuth parameters
        const chainId = BigInt(await publicClient.getChainId());
        const indexLimit = 10n;
        const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

        // Construct message to sign
        const messageHash = keccak256(
          encodeAbiParameters(
            [
              { type: "uint256" },
              { type: "address" },
              { type: "uint64" },
              { type: "uint256" },
              { type: "uint256" },
              { type: "address" },
              { type: "address" }
            ],
            [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, erc1271Wallet.address]
          )
        );

        // Sign with wallet owner's private key (wallet will validate this via ERC-1271)
        const signature = await walletOwner.signMessage({
          message: { raw: messageHash }
        });

        // Construct feedbackAuth with smart contract wallet as signer
        const feedbackAuthEncoded = encodeAbiParameters(
          [
            { type: "uint256" },
            { type: "address" },
            { type: "uint64" },
            { type: "uint256" },
            { type: "uint256" },
            { type: "address" },
            { type: "address" }
          ],
          [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, erc1271Wallet.address]
        );
        const feedbackAuth = (feedbackAuthEncoded + signature.slice(2)) as `0x${string}`;

        // Give feedback - should succeed with ERC-1271 validation
        await reputationRegistry.write.giveFeedback(
          [
            agentId,
            92,
            keccak256(toHex("erc1271")),
            keccak256(toHex("test")),
            "ipfs://erc1271-feedback",
            keccak256(toHex("erc1271-content")),
            feedbackAuth
          ],
          { account: client.account }
        );

        // Verify feedback was recorded
        const feedback = await reputationRegistry.read.readFeedback([agentId, client.account.address, 1n]);
        assert.equal(feedback[0], 92);
        assert.equal(feedback[1], keccak256(toHex("erc1271")));
      });

      it("Should reject feedbackAuth with invalid ERC-1271 signature", async function () {
        const identityRegistry = await viem.deployContract("IdentityRegistry");
        const reputationRegistry = await viem.deployContract("ReputationRegistry", [
          identityRegistry.address,
        ]);

        const [agentOwner, walletOwner, client, attacker] = await viem.getWalletClients();

        // Deploy agent
        const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
        const agentId = await getAgentIdFromRegistration(txHash);

        // Deploy ERC-1271 wallet owned by walletOwner
        const erc1271Wallet = await viem.deployContract("MockERC1271Wallet", [walletOwner.account.address]);

        // Transfer agent to wallet
        await identityRegistry.write.transferFrom(
          [agentOwner.account.address, erc1271Wallet.address, agentId],
          { account: agentOwner.account }
        );

        const chainId = BigInt(await publicClient.getChainId());
        const indexLimit = 10n;
        const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

        const messageHash = keccak256(
          encodeAbiParameters(
            [
              { type: "uint256" },
              { type: "address" },
              { type: "uint64" },
              { type: "uint256" },
              { type: "uint256" },
              { type: "address" },
              { type: "address" }
            ],
            [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, erc1271Wallet.address]
          )
        );

        // Sign with ATTACKER's key (not the wallet owner)
        const badSignature = await attacker.signMessage({
          message: { raw: messageHash }
        });

        const feedbackAuthEncoded = encodeAbiParameters(
          [
            { type: "uint256" },
            { type: "address" },
            { type: "uint64" },
            { type: "uint256" },
            { type: "uint256" },
            { type: "address" },
            { type: "address" }
          ],
          [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, erc1271Wallet.address]
        );
        const feedbackAuth = (feedbackAuthEncoded + badSignature.slice(2)) as `0x${string}`;

        // Should reject - wallet will return invalid magic value
        await assert.rejects(
          reputationRegistry.write.giveFeedback(
            [
              agentId,
              92,
              keccak256(toHex("erc1271")),
              keccak256(toHex("test")),
              "ipfs://feedback",
              keccak256(toHex("content")),
              feedbackAuth
            ],
            { account: client.account }
          )
        );
      });

      it("Should accept feedbackAuth from ERC-1271 wallet with approved operator", async function () {
        const identityRegistry = await viem.deployContract("IdentityRegistry");
        const reputationRegistry = await viem.deployContract("ReputationRegistry", [
          identityRegistry.address,
        ]);

        const [agentOwner, walletOwner, client, operator] = await viem.getWalletClients();

        // Deploy agent
        const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
        const agentId = await getAgentIdFromRegistration(txHash);

        // Deploy ERC-1271 wallet and transfer agent ownership
        const erc1271Wallet = await viem.deployContract("MockERC1271Wallet", [walletOwner.account.address]);
        await identityRegistry.write.transferFrom(
          [agentOwner.account.address, erc1271Wallet.address, agentId],
          { account: agentOwner.account }
        );

        // Wallet approves operator (using signTypedData or similar in real scenario)
        // For this test, we'll have walletOwner sign as if they're the operator
        const chainId = BigInt(await publicClient.getChainId());
        const indexLimit = 10n;
        const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

        const messageHash = keccak256(
          encodeAbiParameters(
            [
              { type: "uint256" },
              { type: "address" },
              { type: "uint64" },
              { type: "uint256" },
              { type: "uint256" },
              { type: "address" },
              { type: "address" }
            ],
            [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, erc1271Wallet.address]
          )
        );

        const signature = await walletOwner.signMessage({
          message: { raw: messageHash }
        });

        const feedbackAuthEncoded = encodeAbiParameters(
          [
            { type: "uint256" },
            { type: "address" },
            { type: "uint64" },
            { type: "uint256" },
            { type: "uint256" },
            { type: "address" },
            { type: "address" }
          ],
          [agentId, client.account.address, indexLimit, expiry, chainId, identityRegistry.address, erc1271Wallet.address]
        );
        const feedbackAuth = (feedbackAuthEncoded + signature.slice(2)) as `0x${string}`;

        // Should succeed
        await reputationRegistry.write.giveFeedback(
          [
            agentId,
            88,
            keccak256(toHex("wallet")),
            keccak256(toHex("operator")),
            "ipfs://feedback",
            keccak256(toHex("content")),
            feedbackAuth
          ],
          { account: client.account }
        );

        const feedback = await reputationRegistry.read.readFeedback([agentId, client.account.address, 1n]);
        assert.equal(feedback[0], 88);
      });

      it("Should handle multiple feedbacks with ERC-1271 wallet signer", async function () {
        const identityRegistry = await viem.deployContract("IdentityRegistry");
        const reputationRegistry = await viem.deployContract("ReputationRegistry", [
          identityRegistry.address,
        ]);

        const [agentOwner, walletOwner, client1, client2] = await viem.getWalletClients();

        // Deploy agent
        const txHash = await identityRegistry.write.register(["ipfs://agent"], { account: agentOwner.account });
        const agentId = await getAgentIdFromRegistration(txHash);

        // Deploy ERC-1271 wallet
        const erc1271Wallet = await viem.deployContract("MockERC1271Wallet", [walletOwner.account.address]);
        await identityRegistry.write.transferFrom(
          [agentOwner.account.address, erc1271Wallet.address, agentId],
          { account: agentOwner.account }
        );

        const chainId = BigInt(await publicClient.getChainId());
        const indexLimit = 100n;
        const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

        // Create feedbackAuth for client1
        const messageHash1 = keccak256(
          encodeAbiParameters(
            [
              { type: "uint256" },
              { type: "address" },
              { type: "uint64" },
              { type: "uint256" },
              { type: "uint256" },
              { type: "address" },
              { type: "address" }
            ],
            [agentId, client1.account.address, indexLimit, expiry, chainId, identityRegistry.address, erc1271Wallet.address]
          )
        );

        const signature1 = await walletOwner.signMessage({ message: { raw: messageHash1 } });
        const feedbackAuth1 = (encodeAbiParameters(
          [
            { type: "uint256" },
            { type: "address" },
            { type: "uint64" },
            { type: "uint256" },
            { type: "uint256" },
            { type: "address" },
            { type: "address" }
          ],
          [agentId, client1.account.address, indexLimit, expiry, chainId, identityRegistry.address, erc1271Wallet.address]
        ) + signature1.slice(2)) as `0x${string}`;

        // Create feedbackAuth for client2
        const messageHash2 = keccak256(
          encodeAbiParameters(
            [
              { type: "uint256" },
              { type: "address" },
              { type: "uint64" },
              { type: "uint256" },
              { type: "uint256" },
              { type: "address" },
              { type: "address" }
            ],
            [agentId, client2.account.address, indexLimit, expiry, chainId, identityRegistry.address, erc1271Wallet.address]
          )
        );

        const signature2 = await walletOwner.signMessage({ message: { raw: messageHash2 } });
        const feedbackAuth2 = (encodeAbiParameters(
          [
            { type: "uint256" },
            { type: "address" },
            { type: "uint64" },
            { type: "uint256" },
            { type: "uint256" },
            { type: "address" },
            { type: "address" }
          ],
          [agentId, client2.account.address, indexLimit, expiry, chainId, identityRegistry.address, erc1271Wallet.address]
        ) + signature2.slice(2)) as `0x${string}`;

        // Give feedback from both clients
        await reputationRegistry.write.giveFeedback(
          [agentId, 85, keccak256(toHex("tag1")), keccak256(toHex("tag2")), "ipfs://f1", keccak256(toHex("c1")), feedbackAuth1],
          { account: client1.account }
        );

        await reputationRegistry.write.giveFeedback(
          [agentId, 95, keccak256(toHex("tag1")), keccak256(toHex("tag2")), "ipfs://f2", keccak256(toHex("c2")), feedbackAuth2],
          { account: client2.account }
        );

        // Verify summary
        const summary = await reputationRegistry.read.getSummary([
          agentId,
          [client1.account.address, client2.account.address],
          "0x0000000000000000000000000000000000000000000000000000000000000000",
          "0x0000000000000000000000000000000000000000000000000000000000000000"
        ]);

        assert.equal(summary[0], 2n); // count
        assert.equal(summary[1], 90); // average = (85 + 95) / 2
      });
    });
  });

  describe("ValidationRegistry", async function () {
    it("Should create validation request", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, validator] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const requestUri = "ipfs://validation-request";
      const requestHash = keccak256(toHex("request data"));

      await viem.assertions.emitWithArgs(
        validationRegistry.write.validationRequest([
          validator.account.address,
          agentId,
          requestUri,
          requestHash,
        ]),
        validationRegistry,
        "ValidationRequest",
        [getAddress(validator.account.address), agentId, requestUri, requestHash]
      );

      // Check status was created
      const status = await validationRegistry.read.validations([requestHash]);
      assert.equal(status[0].toLowerCase(), validator.account.address.toLowerCase()); // validatorAddress
      assert.equal(status[1], agentId); // agentId
      assert.equal(status[2], 0); // response (initial)
    });

    it("Should submit validation response", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, validator] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const requestUri = "ipfs://validation-request";
      const requestHash = keccak256(toHex("request data"));

      await validationRegistry.write.validationRequest([
        validator.account.address,
        agentId,
        requestUri,
        requestHash,
      ]);

      const response = 100;
      const responseUri = "ipfs://validation-response";
      const responseHash = keccak256(toHex("response data"));
      const tag = keccak256(toHex("passed"));

      await viem.assertions.emitWithArgs(
        validationRegistry.write.validationResponse(
          [requestHash, response, responseUri, responseHash, tag],
          { account: validator.account }
        ),
        validationRegistry,
        "ValidationResponse",
        [getAddress(validator.account.address), agentId, requestHash, response, responseUri, responseHash, tag]
      );

      // Check status was updated (now returns responseHash too)
      const statusResult = await validationRegistry.read.getValidationStatus([requestHash]);
      assert.equal(statusResult[0].toLowerCase(), validator.account.address.toLowerCase());
      assert.equal(statusResult[1], agentId);
      assert.equal(statusResult[2], response);
      assert.equal(statusResult[3], responseHash); // responseHash
      assert.equal(statusResult[4], tag); // tag
    });

    it("Should reject duplicate validation requests", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, validator] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const requestUri = "ipfs://validation-request";
      const requestHash = keccak256(toHex("request data"));

      await validationRegistry.write.validationRequest([
        validator.account.address,
        agentId,
        requestUri,
        requestHash,
      ]);

      // Try to create duplicate request
      await assert.rejects(
        validationRegistry.write.validationRequest([
          validator.account.address,
          agentId,
          requestUri,
          requestHash,
        ])
      );
    });

    it("Should only allow validator to respond", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, validator, attacker] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const requestUri = "ipfs://validation-request";
      const requestHash = keccak256(toHex("request data"));

      await validationRegistry.write.validationRequest([
        validator.account.address,
        agentId,
        requestUri,
        requestHash,
      ]);

      // Try to respond as non-validator
      await assert.rejects(
        validationRegistry.write.validationResponse(
          [requestHash, 100, "ipfs://fake", keccak256(toHex("fake")), keccak256(toHex("tag"))],
          { account: attacker.account }
        )
      );
    });

    it("Should reject response > 100", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, validator] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const requestHash = keccak256(toHex("request data"));

      await validationRegistry.write.validationRequest([
        validator.account.address,
        agentId,
        "ipfs://req",
        requestHash,
      ]);

      await assert.rejects(
        validationRegistry.write.validationResponse(
          [requestHash, 101, "ipfs://resp", keccak256(toHex("resp")), keccak256(toHex("tag"))],
          { account: validator.account }
        )
      );
    });

    it("Should get validation summary and track validations", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, validator1, validator2] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const tag = keccak256(toHex("quality"));

      // Create 2 validation requests
      const req1 = keccak256(toHex("request1"));
      const req2 = keccak256(toHex("request2"));

      await validationRegistry.write.validationRequest([validator1.account.address, agentId, "ipfs://req1", req1]);
      await validationRegistry.write.validationRequest([validator2.account.address, agentId, "ipfs://req2", req2]);

      // Respond with scores
      await validationRegistry.write.validationResponse(
        [req1, 80, "ipfs://resp1", keccak256(toHex("r1")), tag],
        { account: validator1.account }
      );
      await validationRegistry.write.validationResponse(
        [req2, 100, "ipfs://resp2", keccak256(toHex("r2")), tag],
        { account: validator2.account }
      );

      // Get summary
      const summary = await validationRegistry.read.getSummary([agentId, [], "0x0000000000000000000000000000000000000000000000000000000000000000"]);
      assert.equal(summary[0], 2n); // count
      assert.equal(summary[1], 90); // avg = (80 + 100) / 2

      // Get agent validations
      const validations = await validationRegistry.read.getAgentValidations([agentId]);
      assert.equal(validations.length, 2);

      // Get validator requests
      const requests = await validationRegistry.read.getValidatorRequests([validator1.account.address]);
      assert.equal(requests.length, 1);
      assert.equal(requests[0], req1);
    });

    it("Should only allow agent owner to request validation", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, attacker, validator] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const requestHash = keccak256(toHex("request"));

      // Attacker tries to request validation for someone else's agent
      await assert.rejects(
        validationRegistry.write.validationRequest(
          [validator.account.address, agentId, "ipfs://req", requestHash],
          { account: attacker.account }
        )
      );

      // Owner can request validation
      await validationRegistry.write.validationRequest([
        validator.account.address,
        agentId,
        "ipfs://req",
        requestHash,
      ]);
    });

    /**
     * "validationResponse() can be called multiple times for the same requestHash, enabling use cases like
     * progressive validation states (e.g., \"soft finality\" and \"hard finality\" using tag) or updates to
     * validation status."
     */
    it("Should allow multiple validation responses for same request", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, validator] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const requestHash = keccak256(toHex("request data"));

      // Create request
      await validationRegistry.write.validationRequest([
        validator.account.address,
        agentId,
        "ipfs://request",
        requestHash,
      ]);

      // First response - soft finality
      const softFinalityTag = keccak256(toHex("soft_finality"));
      await validationRegistry.write.validationResponse(
        [requestHash, 80, "ipfs://response1", keccak256(toHex("r1")), softFinalityTag],
        { account: validator.account }
      );

      // Check first response
      let status = await validationRegistry.read.getValidationStatus([requestHash]);
      assert.equal(status[2], 80); // response
      assert.equal(status[4], softFinalityTag); // tag (responseHash is at [3])

      // Second response - hard finality (update)
      const hardFinalityTag = keccak256(toHex("hard_finality"));
      await validationRegistry.write.validationResponse(
        [requestHash, 100, "ipfs://response2", keccak256(toHex("r2")), hardFinalityTag],
        { account: validator.account }
      );

      // Check updated response
      status = await validationRegistry.read.getValidationStatus([requestHash]);
      assert.equal(status[2], 100); // updated response
      assert.equal(status[4], hardFinalityTag); // updated tag (responseHash is at [3])
    });

    /**
     * "When the Validation Registry is deployed, the identityRegistry address is passed to the constructor and
     * is visible by calling getIdentityRegistry()"
     */
    it("Should return the identity registry address", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const retrievedAddress = await validationRegistry.read.getIdentityRegistry();
      assert.equal(retrievedAddress.toLowerCase(), identityRegistry.address.toLowerCase());
    });

    /**
     * "The response is a value between 0 and 100, which can be used as binary (0 for failed, 100 for passed)
     * or with intermediate values for validations with a spectrum of outcomes."
     */
    it("Should accept response of 0 (failed)", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, validator] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const requestHash = keccak256(toHex("request"));

      await validationRegistry.write.validationRequest([
        validator.account.address,
        agentId,
        "ipfs://req",
        requestHash,
      ]);

      // Response of 0 should be valid (failed validation)
      await validationRegistry.write.validationResponse(
        [requestHash, 0, "ipfs://failed", keccak256(toHex("fail")), keccak256(toHex("failed"))],
        { account: validator.account }
      );

      const status = await validationRegistry.read.getValidationStatus([requestHash]);
      assert.equal(status[2], 0);
    });

    /**
     * "The response is a value between 0 and 100, which can be used as binary (0 for failed, 100 for passed)
     * or with intermediate values for validations with a spectrum of outcomes."
     */
    it("Should accept intermediate response values", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, validator] = await viem.getWalletClients();
      const txHash = await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = await getAgentIdFromRegistration(txHash);

      const requestHash = keccak256(toHex("request"));

      await validationRegistry.write.validationRequest([
        validator.account.address,
        agentId,
        "ipfs://req",
        requestHash,
      ]);

      // Intermediate value (partial validation)
      await validationRegistry.write.validationResponse(
        [requestHash, 67, "ipfs://partial", keccak256(toHex("partial")), keccak256(toHex("partial"))],
        { account: validator.account }
      );

      const status = await validationRegistry.read.getValidationStatus([requestHash]);
      assert.equal(status[2], 67);
    });
  });
});
