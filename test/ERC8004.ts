import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { encodeAbiParameters, encodePacked, getAddress, keccak256, toHex } from "viem";

describe("ERC8004 Registries", async function () {
  const { viem } = await network.connect();
  const publicClient = await viem.getPublicClient();

  describe("IdentityRegistry", async function () {
    it("Should register an agent with tokenURI", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const [owner] = await viem.getWalletClients();

      const tokenURI = "ipfs://QmTest123";
      await viem.assertions.emitWithArgs(
        identityRegistry.write.register([tokenURI]),
        identityRegistry,
        "Registered",
        [0n, tokenURI, getAddress(owner.account.address)]
      );

      // Verify tokenURI was set
      const retrievedURI = await identityRegistry.read.tokenURI([0n]);
      assert.equal(retrievedURI, tokenURI);

      // Verify owner
      const tokenOwner = await identityRegistry.read.ownerOf([0n]);
      assert.equal(tokenOwner.toLowerCase(), owner.account.address.toLowerCase());
    });

    it("Should auto-increment agentId", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");

      await identityRegistry.write.register(["ipfs://agent1"]);
      await identityRegistry.write.register(["ipfs://agent2"]);
      await identityRegistry.write.register(["ipfs://agent3"]);

      const uri1 = await identityRegistry.read.tokenURI([0n]);
      const uri2 = await identityRegistry.read.tokenURI([1n]);
      const uri3 = await identityRegistry.read.tokenURI([2n]);

      assert.equal(uri1, "ipfs://agent1");
      assert.equal(uri2, "ipfs://agent2");
      assert.equal(uri3, "ipfs://agent3");
    });

    it("Should set and get metadata", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const [owner] = await viem.getWalletClients();

      await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = 0n;

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

      await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = 0n;

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

      const hash = await identityRegistry.write.register([tokenURI, metadata]);

      // Verify metadata was set
      const wallet = await identityRegistry.read.getMetadata([0n, "agentWallet"]);
      const name = await identityRegistry.read.getMetadata([0n, "agentName"]);

      assert.equal(wallet, metadata[0].value);
      assert.equal(name, metadata[1].value);
    });
  });

  describe("ReputationRegistry", async function () {
    it("Should give feedback to an agent", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [client] = await viem.getWalletClients();
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
      const score = 85;
      const tag1 = keccak256(toHex("quality"));
      const tag2 = keccak256(toHex("speed"));
      const fileuri = "ipfs://feedback1";
      const filehash = keccak256(toHex("feedback content"));

      await viem.assertions.emitWithArgs(
        reputationRegistry.write.giveFeedback([
          agentId,
          score,
          tag1,
          tag2,
          fileuri,
          filehash,
          "0x", // feedbackAuth not verified yet
        ]),
        reputationRegistry,
        "NewFeedback",
        [agentId, getAddress(client.account.address), score, tag1, tag2, fileuri, filehash]
      );

      // Read feedback back
      const feedback = await reputationRegistry.read.readFeedback([
        agentId,
        client.account.address,
        0n,
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

      const [client] = await viem.getWalletClients();
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
      await reputationRegistry.write.giveFeedback([
        agentId,
        90,
        keccak256(toHex("tag1")),
        keccak256(toHex("tag2")),
        "ipfs://feedback",
        keccak256(toHex("content")),
        "0x",
      ]);

      // Revoke feedback
      await viem.assertions.emitWithArgs(
        reputationRegistry.write.revokeFeedback([agentId, 0n]),
        reputationRegistry,
        "FeedbackRevoked",
        [agentId, getAddress(client.account.address), 0n]
      );

      // Verify feedback is revoked
      const feedback = await reputationRegistry.read.readFeedback([
        agentId,
        client.account.address,
        0n,
      ]);
      assert.equal(feedback[3], true); // isRevoked
    });

    it("Should append response to feedback", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [client, responder] = await viem.getWalletClients();
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
      await reputationRegistry.write.giveFeedback([
        agentId,
        75,
        keccak256(toHex("tag1")),
        keccak256(toHex("tag2")),
        "ipfs://feedback",
        keccak256(toHex("content")),
        "0x",
      ]);

      const responseUri = "ipfs://response1";
      const responseHash = keccak256(toHex("response content"));

      await viem.assertions.emitWithArgs(
        reputationRegistry.write.appendResponse(
          [agentId, client.account.address, 0n, responseUri, responseHash],
          { account: responder.account }
        ),
        reputationRegistry,
        "ResponseAppended",
        [agentId, getAddress(client.account.address), 0n, getAddress(responder.account.address), responseUri]
      );
    });

    it("Should track multiple feedbacks from same client", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [client] = await viem.getWalletClients();
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;

      // Give 3 feedbacks
      for (let i = 0; i < 3; i++) {
        await reputationRegistry.write.giveFeedback([
          agentId,
          80 + i,
          keccak256(toHex("tag1")),
          keccak256(toHex("tag2")),
          `ipfs://feedback${i}`,
          keccak256(toHex(`content${i}`)),
          "0x",
        ]);
      }

      const lastIndex = await reputationRegistry.read.getLastIndex([
        agentId,
        client.account.address,
      ]);
      assert.equal(lastIndex, 2n); // 0, 1, 2

      // Read all feedbacks
      const fb0 = await reputationRegistry.read.readFeedback([agentId, client.account.address, 0n]);
      const fb1 = await reputationRegistry.read.readFeedback([agentId, client.account.address, 1n]);
      const fb2 = await reputationRegistry.read.readFeedback([agentId, client.account.address, 2n]);

      assert.equal(fb0[0], 80);
      assert.equal(fb1[0], 81);
      assert.equal(fb2[0], 82);
    });

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

    it("Should allow feedback without auth (empty bytes)", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      await identityRegistry.write.register(["ipfs://agent"]);

      // Empty auth should be accepted
      await reputationRegistry.write.giveFeedback([
        0n,
        95,
        keccak256(toHex("tag1")),
        keccak256(toHex("tag2")),
        "ipfs://feedback",
        keccak256(toHex("content")),
        "0x",
      ]);

      const feedback = await reputationRegistry.read.readFeedback([0n, (await viem.getWalletClients())[0].account.address, 0n]);
      assert.equal(feedback[0], 95);
    });

    it("Should calculate summary with average score", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [client1, client2] = await viem.getWalletClients();
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
      const tag1 = keccak256(toHex("service"));
      const tag2 = keccak256(toHex("fast"));

      // Client 1 gives 2 feedbacks
      await reputationRegistry.write.giveFeedback([
        agentId, 80, tag1, tag2, "ipfs://f1", keccak256(toHex("c1")), "0x"
      ]);
      await reputationRegistry.write.giveFeedback([
        agentId, 90, tag1, tag2, "ipfs://f2", keccak256(toHex("c2")), "0x"
      ]);

      // Client 2 gives 1 feedback
      await reputationRegistry.write.giveFeedback(
        [agentId, 100, tag1, tag2, "ipfs://f3", keccak256(toHex("c3")), "0x"],
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

      const [client] = await viem.getWalletClients();
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
      const tagA = keccak256(toHex("tagA"));
      const tagB = keccak256(toHex("tagB"));
      const tagC = keccak256(toHex("tagC"));

      // Give feedbacks with different tags
      await reputationRegistry.write.giveFeedback([agentId, 80, tagA, tagB, "", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x"]);
      await reputationRegistry.write.giveFeedback([agentId, 90, tagA, tagC, "", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x"]);
      await reputationRegistry.write.giveFeedback([agentId, 100, tagB, tagC, "", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x"]);

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

      const [client1, client2] = await viem.getWalletClients();
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
      const tag1 = keccak256(toHex("quality"));

      // Client1: 2 feedbacks
      await reputationRegistry.write.giveFeedback([agentId, 80, tag1, "0x0000000000000000000000000000000000000000000000000000000000000000", "", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x"]);
      await reputationRegistry.write.giveFeedback([agentId, 90, tag1, "0x0000000000000000000000000000000000000000000000000000000000000000", "", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x"]);

      // Client2: 1 feedback
      await reputationRegistry.write.giveFeedback(
        [agentId, 100, tag1, "0x0000000000000000000000000000000000000000000000000000000000000000", "", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x"],
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

      const [client, responder1, responder2] = await viem.getWalletClients();
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;

      // Give feedback
      await reputationRegistry.write.giveFeedback([
        agentId, 85, "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000", "", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x"
      ]);

      // Append 2 responses from different responders
      await reputationRegistry.write.appendResponse(
        [agentId, client.account.address, 0n, "ipfs://response1", "0x0000000000000000000000000000000000000000000000000000000000000000"],
        { account: responder1.account }
      );
      await reputationRegistry.write.appendResponse(
        [agentId, client.account.address, 0n, "ipfs://response2", "0x0000000000000000000000000000000000000000000000000000000000000000"],
        { account: responder2.account }
      );

      // Get response count (no filter)
      const totalCount = await reputationRegistry.read.getResponseCount([
        agentId, client.account.address, 0n, []
      ]);
      assert.equal(totalCount, 2n);

      // Get response count (filter by responder1)
      const responder1Count = await reputationRegistry.read.getResponseCount([
        agentId, client.account.address, 0n, [responder1.account.address]
      ]);
      assert.equal(responder1Count, 1n);
    });

    it("Should verify feedbackAuth signature from agent owner", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client] = await viem.getWalletClients();

      // Register agent (owner is agentOwner)
      await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = 0n;

      // Prepare feedbackAuth parameters
      const chainId = BigInt(await publicClient.getChainId());
      const indexLimit = 10n;
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour from now

      // Construct message to sign (using encodePacked to match contract's abi.encodePacked)
      const messageHash = keccak256(
        encodePacked(
          ["uint256", "address", "uint64", "uint256", "uint256", "address", "address"],
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
      const feedback = await reputationRegistry.read.readFeedback([agentId, client.account.address, 0n]);
      assert.equal(feedback[0], 95);
    });

    it("Should reject feedbackAuth with invalid signature", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client, attacker] = await viem.getWalletClients();

      // Register agent (owner is agentOwner)
      await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = 0n;

      const chainId = BigInt(await publicClient.getChainId());
      const indexLimit = 10n;
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

      // Construct message
      const messageHash = keccak256(
        encodePacked(
          ["uint256", "address", "uint64", "uint256", "uint256", "address", "address"],
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
      await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = 0n;

      const chainId = BigInt(await publicClient.getChainId());
      const indexLimit = 10n;
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

      // Construct message claiming attacker is the signer
      const messageHash = keccak256(
        encodePacked(
          ["uint256", "address", "uint64", "uint256", "uint256", "address", "address"],
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
      await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = 0n;

      // Owner approves operator
      await identityRegistry.write.setApprovalForAll([operator.account.address, true]);

      const chainId = BigInt(await publicClient.getChainId());
      const indexLimit = 10n;
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

      // Operator signs the feedbackAuth
      const messageHash = keccak256(
        encodePacked(
          ["uint256", "address", "uint64", "uint256", "uint256", "address", "address"],
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

      const feedback = await reputationRegistry.read.readFeedback([agentId, client.account.address, 0n]);
      assert.equal(feedback[0], 88);
    });

    it("Should reject expired feedbackAuth", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const reputationRegistry = await viem.deployContract("ReputationRegistry", [
        identityRegistry.address,
      ]);

      const [agentOwner, client] = await viem.getWalletClients();

      await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = 0n;

      const chainId = BigInt(await publicClient.getChainId());
      const indexLimit = 10n;
      const expiry = BigInt(Math.floor(Date.now() / 1000) - 3600); // 1 hour ago (expired)

      const messageHash = keccak256(
        encodePacked(
          ["uint256", "address", "uint64", "uint256", "uint256", "address", "address"],
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

      await identityRegistry.write.register(["ipfs://agent"]);
      const agentId = 0n;

      const chainId = BigInt(await publicClient.getChainId());
      const indexLimit = 1n; // Only allow 1 feedback
      const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);

      const messageHash = keccak256(
        encodePacked(
          ["uint256", "address", "uint64", "uint256", "uint256", "address", "address"],
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
  });

  describe("ValidationRegistry", async function () {
    it("Should create validation request", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, validator] = await viem.getWalletClients();
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
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
      const status = await validationRegistry.read.status([requestHash]);
      assert.equal(status[0].toLowerCase(), validator.account.address.toLowerCase()); // validatorAddress
      assert.equal(status[1], agentId); // agentId
      assert.equal(status[2], 0); // response (initial)
      assert.equal(status[5], true); // exists
    });

    it("Should submit validation response", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, validator] = await viem.getWalletClients();
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
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
        [getAddress(validator.account.address), agentId, requestHash, response, responseUri, tag]
      );

      // Check status was updated
      const statusResult = await validationRegistry.read.getValidationStatus([requestHash]);
      assert.equal(statusResult[0].toLowerCase(), validator.account.address.toLowerCase());
      assert.equal(statusResult[1], agentId);
      assert.equal(statusResult[2], response);
      assert.equal(statusResult[3], tag);
    });

    it("Should reject duplicate validation requests", async function () {
      const identityRegistry = await viem.deployContract("IdentityRegistry");
      const validationRegistry = await viem.deployContract("ValidationRegistry", [
        identityRegistry.address,
      ]);

      const [owner, validator] = await viem.getWalletClients();
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
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
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
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
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
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
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
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
      await identityRegistry.write.register(["ipfs://agent"]);

      const agentId = 0n;
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
  });
});
