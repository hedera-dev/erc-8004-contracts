// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract IdentityRegistry is ERC721URIStorage, Ownable {
    uint256 private _nextId = 1;

    // agentId => key => value
    mapping(uint256 => mapping(string => bytes)) private _metadata;

    struct MetadataEntry {
        string key;
        bytes value;
    }

    event Registered(uint256 indexed agentId, string tokenURI, address indexed owner);
    event MetadataSet(uint256 indexed agentId, string indexed indexedKey, string key, bytes value);

    constructor() ERC721("AgentIdentity", "AID") Ownable(msg.sender) {}

    function register() external returns (uint256 agentId) {
        agentId = _nextId++;
        _safeMint(msg.sender, agentId);
        emit Registered(agentId, "", msg.sender);
    }

    function register(string memory tokenURI) external returns (uint256 agentId) {
        agentId = _nextId++;
        _safeMint(msg.sender, agentId);
        _setTokenURI(agentId, tokenURI);
        emit Registered(agentId, tokenURI, msg.sender);
    }

    function register(string memory tokenURI, MetadataEntry[] memory metadata) external returns (uint256 agentId) {
        agentId = _nextId++;
        _safeMint(msg.sender, agentId);
        _setTokenURI(agentId, tokenURI);
        emit Registered(agentId, tokenURI, msg.sender);

        for (uint256 i = 0; i < metadata.length; i++) {
            _metadata[agentId][metadata[i].key] = metadata[i].value;
            emit MetadataSet(agentId, metadata[i].key, metadata[i].key, metadata[i].value);
        }
    }

    function getMetadata(uint256 agentId, string memory key) external view returns (bytes memory) {
        return _metadata[agentId][key];
    }

    function setMetadata(uint256 agentId, string memory key, bytes memory value) external {
        require(
            msg.sender == _ownerOf(agentId) ||
            isApprovedForAll(_ownerOf(agentId), msg.sender) ||
            msg.sender == getApproved(agentId),
            "Not authorized"
        );
        _metadata[agentId][key] = value;
        emit MetadataSet(agentId, key, key, value);
    }

    function setTokenURI(uint256 agentId, string calldata newURI) external {
        address owner = ownerOf(agentId);
        require(
            msg.sender == owner ||
            isApprovedForAll(owner, msg.sender) ||
            msg.sender == getApproved(agentId), // optional: per-token approval
            "Not authorized"
        );
        _setTokenURI(agentId, newURI);
        // (No new event required by spec; Registered is only for minting.)
    }
}

