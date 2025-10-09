// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";

interface IIdentityRegistry {
    function ownerOf(uint256 tokenId) external view returns (address);
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}

/// @notice Minimal, compilable scaffold of ERC-8004 Reputation Registry.
/// - Stores identityRegistry address
/// - Emits NewFeedback / FeedbackRevoked / ResponseAppended
/// - Stores small amount of data so we can deploy & test now
contract ReputationRegistry {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    address public immutable identityRegistry;

    event NewFeedback(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint8 score,
        bytes32 indexed tag1,
        bytes32 tag2,
        string fileuri,
        bytes32 filehash
    );

    event FeedbackRevoked(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 indexed feedbackIndex
    );

    event ResponseAppended(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 feedbackIndex,
        address indexed responder,
        string responseUri
    );

    struct Feedback {
        uint8 score;
        bytes32 tag1;
        bytes32 tag2;
        bool isRevoked;
    }

    struct Response {
        address responder;
        string responseUri;
        bytes32 responseHash;
    }

    // agentId => client => list of feedback
    mapping(uint256 => mapping(address => Feedback[])) private _feedbacks;

    // agentId => clientAddress => feedbackIndex => list of responses
    mapping(uint256 => mapping(address => mapping(uint64 => Response[]))) private _responses;

    // Track all unique clients that have given feedback for each agent
    mapping(uint256 => address[]) private _clients;
    mapping(uint256 => mapping(address => bool)) private _clientExists;

    constructor(address _identityRegistry) {
        require(_identityRegistry != address(0), "bad identity");
        identityRegistry = _identityRegistry;
    }

    function getIdentityRegistry() external view returns (address) {
        return identityRegistry;
    }

    function giveFeedback(
        uint256 agentId,
        uint8 score,
        bytes32 tag1,
        bytes32 tag2,
        string calldata fileuri,
        bytes32 filehash,
        bytes calldata feedbackAuth
    ) external {
        require(score <= 100, "score>100");

        // Verify agent exists
        require(_agentExists(agentId), "Agent does not exist");

        // Verify feedbackAuth signature
        if (feedbackAuth.length > 0) {
            _verifyFeedbackAuth(agentId, msg.sender, feedbackAuth);
        }

        // track new client
        if (!_clientExists[agentId][msg.sender]) {
            _clients[agentId].push(msg.sender);
            _clientExists[agentId][msg.sender] = true;
        }

        _feedbacks[agentId][msg.sender].push(Feedback(score, tag1, tag2, false));
        emit NewFeedback(agentId, msg.sender, score, tag1, tag2, fileuri, filehash);
    }

    function _verifyFeedbackAuth(
        uint256 agentId,
        address clientAddress,
        bytes calldata feedbackAuth
    ) internal view {
        require(
            IIdentityRegistry(identityRegistry).ownerOf(agentId) != address(0),
            "Unregistered agent"
        );
        // Decode feedbackAuth: first 224 bytes are ABI-encoded params, rest is signature
        // 32 + 32 + 32 + 32 + 32 + 32 + 32 = 224 bytes for 7 params
        require(feedbackAuth.length >= 289, "Invalid auth length"); // 224 + 65 for signature

        // Decode the first 224 bytes
        (
            uint256 authAgentId,
            address authClientAddress,
            uint64 indexLimit,
            uint256 expiry,
            uint256 authChainId,
            address authIdentityRegistry,
            address signerAddress
        ) = abi.decode(feedbackAuth[:224], (uint256, address, uint64, uint256, uint256, address, address));

        // Extract signature from remaining bytes
        bytes memory signature = feedbackAuth[224:];

        // Verify parameters
        require(authAgentId == agentId, "AgentId mismatch");
        require(authClientAddress == clientAddress, "Client mismatch");
        require(block.timestamp < expiry, "Auth expired");
        require(authChainId == block.chainid, "ChainId mismatch");
        require(authIdentityRegistry == identityRegistry, "Registry mismatch");

        uint64 currentIndex = uint64(_feedbacks[agentId][clientAddress].length);
        require(indexLimit > currentIndex, "IndexLimit exceeded");

        // Construct message hash
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                authAgentId,
                authClientAddress,
                indexLimit,
                expiry,
                authChainId,
                authIdentityRegistry,
                signerAddress
            )
        );

        // Verify signature with EIP-191
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address recoveredSigner = ethSignedMessageHash.recover(signature);

        // verify signature: EOA or ERC-1271 contract
        if (recoveredSigner != signerAddress) {
            // if signer is a contract, try ERC-1271
            if (signerAddress.code.length == 0) {
                revert("Invalid signature");
            }
            bytes4 magic = IERC1271(signerAddress).isValidSignature(
                ethSignedMessageHash,
                signature
            );
            require(magic == IERC1271.isValidSignature.selector, "Bad 1271 signature");
        }

        // Verify signerAddress is owner or operator of agentId in IdentityRegistry
        IIdentityRegistry registry = IIdentityRegistry(identityRegistry);
        address owner = registry.ownerOf(authAgentId);
        require(
            signerAddress == owner || registry.isApprovedForAll(owner, signerAddress),
            "Signer not authorized"
        );
    }

    function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external {
        require(feedbackIndex < _feedbacks[agentId][msg.sender].length, "index");
        _feedbacks[agentId][msg.sender][feedbackIndex].isRevoked = true;
        emit FeedbackRevoked(agentId, msg.sender, feedbackIndex);
    }

    function appendResponse(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        string calldata responseUri,
        bytes32 responseHash
    ) external {
        require(feedbackIndex < _feedbacks[agentId][clientAddress].length, "index");

        // Store response
        _responses[agentId][clientAddress][feedbackIndex].push(Response({
            responder: msg.sender,
            responseUri: responseUri,
            responseHash: responseHash
        }));

        emit ResponseAppended(agentId, clientAddress, feedbackIndex, msg.sender, responseUri);
    }

    // Minimal reads for now (enough to test):
    function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64) {
        return uint64(_feedbacks[agentId][clientAddress].length == 0
            ? 0
            : _feedbacks[agentId][clientAddress].length - 1);
    }

    function readFeedback(uint256 agentId, address clientAddress, uint64 index)
        external
        view
        returns (uint8 score, bytes32 tag1, bytes32 tag2, bool isRevoked)
    {
        Feedback memory f = _feedbacks[agentId][clientAddress][index];
        return (f.score, f.tag1, f.tag2, f.isRevoked);
    }

    function getSummary(
        uint256 agentId,
        address[] calldata clientAddresses,
        bytes32 tag1,
        bytes32 tag2
    ) external view returns (uint64 count, uint8 averageScore) {
        uint256 totalScore = 0;
        count = 0;

        // If no client addresses provided, return 0 (to avoid Sybil attacks as per spec)
        if (clientAddresses.length == 0) {
            return (0, 0);
        }

        for (uint256 i = 0; i < clientAddresses.length; i++) {
            address client = clientAddresses[i];
            Feedback[] storage feedbacks = _feedbacks[agentId][client];

            for (uint256 j = 0; j < feedbacks.length; j++) {
                Feedback storage f = feedbacks[j];

                // Skip revoked feedback
                if (f.isRevoked) continue;

                // Apply tag filters (0x0 means no filter)
                bool matchTag1 = (tag1 == bytes32(0)) || (f.tag1 == tag1);
                bool matchTag2 = (tag2 == bytes32(0)) || (f.tag2 == tag2);

                if (matchTag1 && matchTag2) {
                    totalScore += f.score;
                    count++;
                }
            }
        }

        averageScore = count > 0 ? uint8(totalScore / count) : 0;
    }

    function readAllFeedback(
        uint256 agentId,
        address[] calldata clientAddresses,
        bytes32 tag1,
        bytes32 tag2,
        bool includeRevoked
    ) external view returns (
        address[] memory clients,
        uint8[] memory scores,
        bytes32[] memory tag1s,
        bytes32[] memory tag2s,
        bool[] memory revokedStatuses
    ) {
        // First pass: count
        uint256 totalCount = _countMatchingFeedback(agentId, clientAddresses, tag1, tag2, includeRevoked);

        // Allocate arrays
        clients = new address[](totalCount);
        scores = new uint8[](totalCount);
        tag1s = new bytes32[](totalCount);
        tag2s = new bytes32[](totalCount);
        revokedStatuses = new bool[](totalCount);

        // Second pass: fill
        uint256 index = 0;
        for (uint256 i = 0; i < clientAddresses.length; i++) {
            index = _fillFeedbackArrays(
                agentId,
                clientAddresses[i],
                tag1,
                tag2,
                includeRevoked,
                clients,
                scores,
                tag1s,
                tag2s,
                revokedStatuses,
                index
            );
        }
    }

    function _countMatchingFeedback(
        uint256 agentId,
        address[] calldata clientAddresses,
        bytes32 tag1,
        bytes32 tag2,
        bool includeRevoked
    ) internal view returns (uint256 count) {
        for (uint256 i = 0; i < clientAddresses.length; i++) {
            Feedback[] storage feedbacks = _feedbacks[agentId][clientAddresses[i]];
            for (uint256 j = 0; j < feedbacks.length; j++) {
                Feedback storage f = feedbacks[j];
                if (!includeRevoked && f.isRevoked) continue;
                if (_matchesTags(f, tag1, tag2)) count++;
            }
        }
    }

    function _fillFeedbackArrays(
        uint256 agentId,
        address client,
        bytes32 tag1,
        bytes32 tag2,
        bool includeRevoked,
        address[] memory clients,
        uint8[] memory scores,
        bytes32[] memory tag1s,
        bytes32[] memory tag2s,
        bool[] memory revokedStatuses,
        uint256 startIndex
    ) internal view returns (uint256 index) {
        index = startIndex;
        Feedback[] storage feedbacks = _feedbacks[agentId][client];
        for (uint256 j = 0; j < feedbacks.length; j++) {
            Feedback storage f = feedbacks[j];
            if (!includeRevoked && f.isRevoked) continue;
            if (_matchesTags(f, tag1, tag2)) {
                clients[index] = client;
                scores[index] = f.score;
                tag1s[index] = f.tag1;
                tag2s[index] = f.tag2;
                revokedStatuses[index] = f.isRevoked;
                index++;
            }
        }
    }

    function _matchesTags(Feedback storage f, bytes32 tag1, bytes32 tag2) internal view returns (bool) {
        bool matchTag1 = (tag1 == bytes32(0)) || (f.tag1 == tag1);
        bool matchTag2 = (tag2 == bytes32(0)) || (f.tag2 == tag2);
        return matchTag1 && matchTag2;
    }

    function getResponseCount(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        address[] calldata responders
    ) external view returns (uint64) {
        Response[] storage responses = _responses[agentId][clientAddress][feedbackIndex];

        // If no responder filter, return total count
        if (responders.length == 0) {
            return uint64(responses.length);
        }

        // Count responses from specified responders
        uint64 count = 0;
        for (uint256 i = 0; i < responses.length; i++) {
            for (uint256 j = 0; j < responders.length; j++) {
                if (responses[i].responder == responders[j]) {
                    count++;
                    break;
                }
            }
        }
        return count;
    }

    function getClients(uint256 agentId) external view returns (address[] memory) {
        return _clients[agentId];
    }

    function _agentExists(uint256 agentId) internal view returns (bool) {
        try IIdentityRegistry(identityRegistry).ownerOf(agentId) returns (address owner) {
            return owner != address(0);
        } catch {
            return false;
        }
    }
}
