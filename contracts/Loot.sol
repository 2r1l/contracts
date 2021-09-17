pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

abstract contract ERC721Checkpointable is ERC721Enumerable {
    /// @notice Defines decimals as per ERC-20 convention to make integrations with 3rd party governance platforms easier
    uint8 public constant decimals = 0;

    /// @notice A record of each accounts delegate
    mapping(address => address) private _delegates;

    /// @notice A checkpoint for marking number of votes from a given block
    struct Checkpoint {
        uint32 fromBlock;
        uint96 votes;
    }

    /// @notice A record of votes checkpoints for each account, by index
    mapping(address => mapping(uint32 => Checkpoint)) public checkpoints;

    /// @notice The number of checkpoints for each account
    mapping(address => uint32) public numCheckpoints;

    /// @notice The EIP-712 typehash for the contract's domain
    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256('EIP712Domain(string name,uint256 chainId,address verifyingContract)');

    /// @notice The EIP-712 typehash for the delegation struct used by the contract
    bytes32 public constant DELEGATION_TYPEHASH =
        keccak256('Delegation(address delegatee,uint256 nonce,uint256 expiry)');

    /// @notice A record of states for signing / validating signatures
    mapping(address => uint256) public nonces;

    /// @notice An event thats emitted when an account changes its delegate
    event DelegateChanged(address indexed delegator, address indexed fromDelegate, address indexed toDelegate);

    /// @notice An event thats emitted when a delegate account's vote balance changes
    event DelegateVotesChanged(address indexed delegate, uint256 previousBalance, uint256 newBalance);

    /**
     * @notice The votes a delegator can delegate, which is the current balance of the delegator.
     * @dev Used when calling `_delegate()`
     */
    function votesToDelegate(address delegator) public view returns (uint96) {
        return safe96(balanceOf(delegator), 'ERC721Checkpointable::votesToDelegate: amount exceeds 96 bits');
    }

    /**
     * @notice Overrides the standard `Comp.sol` delegates mapping to return
     * the delegator's own address if they haven't delegated.
     * This avoids having to delegate to oneself.
     */
    function delegates(address delegator) public view returns (address) {
        address current = _delegates[delegator];
        return current == address(0) ? delegator : current;
    }

    /**
     * @notice Adapted from `_transferTokens()` in `Comp.sol` to update delegate votes.
     * @dev hooks into OpenZeppelin's `ERC721._transfer`
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal override {
        super._beforeTokenTransfer(from, to, tokenId);

        /// @notice Differs from `_transferTokens()` to use `delegates` override method to simulate auto-delegation
        _moveDelegates(delegates(from), delegates(to), 1);
    }

    /**
     * @notice Delegate votes from `msg.sender` to `delegatee`
     * @param delegatee The address to delegate votes to
     */
    function delegate(address delegatee) public {
        if (delegatee == address(0)) delegatee = msg.sender;
        return _delegate(msg.sender, delegatee);
    }

    /**
     * @notice Delegates votes from signatory to `delegatee`
     * @param delegatee The address to delegate votes to
     * @param nonce The contract state required to match the signature
     * @param expiry The time at which to expire the signature
     * @param v The recovery byte of the signature
     * @param r Half of the ECDSA signature pair
     * @param s Half of the ECDSA signature pair
     */
    function delegateBySig(
        address delegatee,
        uint256 nonce,
        uint256 expiry,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        bytes32 domainSeparator = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name())), getChainId(), address(this))
        );
        bytes32 structHash = keccak256(abi.encode(DELEGATION_TYPEHASH, delegatee, nonce, expiry));
        bytes32 digest = keccak256(abi.encodePacked('\x19\x01', domainSeparator, structHash));
        address signatory = ecrecover(digest, v, r, s);
        require(signatory != address(0), 'ERC721Checkpointable::delegateBySig: invalid signature');
        require(nonce == nonces[signatory]++, 'ERC721Checkpointable::delegateBySig: invalid nonce');
        require(block.timestamp <= expiry, 'ERC721Checkpointable::delegateBySig: signature expired');
        return _delegate(signatory, delegatee);
    }

    /**
     * @notice Gets the current votes balance for `account`
     * @param account The address to get votes balance
     * @return The number of current votes for `account`
     */
    function getCurrentVotes(address account) external view returns (uint96) {
        uint32 nCheckpoints = numCheckpoints[account];
        return nCheckpoints > 0 ? checkpoints[account][nCheckpoints - 1].votes : 0;
    }

    /**
     * @notice Determine the prior number of votes for an account as of a block number
     * @dev Block number must be a finalized block or else this function will revert to prevent misinformation.
     * @param account The address of the account to check
     * @param blockNumber The block number to get the vote balance at
     * @return The number of votes the account had as of the given block
     */
    function getPriorVotes(address account, uint256 blockNumber) public view returns (uint96) {
        require(blockNumber < block.number, 'ERC721Checkpointable::getPriorVotes: not yet determined');

        uint32 nCheckpoints = numCheckpoints[account];
        if (nCheckpoints == 0) {
            return 0;
        }

        // First check most recent balance
        if (checkpoints[account][nCheckpoints - 1].fromBlock <= blockNumber) {
            return checkpoints[account][nCheckpoints - 1].votes;
        }

        // Next check implicit zero balance
        if (checkpoints[account][0].fromBlock > blockNumber) {
            return 0;
        }

        uint32 lower = 0;
        uint32 upper = nCheckpoints - 1;
        while (upper > lower) {
            uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow
            Checkpoint memory cp = checkpoints[account][center];
            if (cp.fromBlock == blockNumber) {
                return cp.votes;
            } else if (cp.fromBlock < blockNumber) {
                lower = center;
            } else {
                upper = center - 1;
            }
        }
        return checkpoints[account][lower].votes;
    }

    function _delegate(address delegator, address delegatee) internal {
        /// @notice differs from `_delegate()` in `Comp.sol` to use `delegates` override method to simulate auto-delegation
        address currentDelegate = delegates(delegator);

        _delegates[delegator] = delegatee;

        emit DelegateChanged(delegator, currentDelegate, delegatee);

        uint96 amount = votesToDelegate(delegator);

        _moveDelegates(currentDelegate, delegatee, amount);
    }

    function _moveDelegates(
        address srcRep,
        address dstRep,
        uint96 amount
    ) internal {
        if (srcRep != dstRep && amount > 0) {
            if (srcRep != address(0)) {
                uint32 srcRepNum = numCheckpoints[srcRep];
                uint96 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;
                uint96 srcRepNew = sub96(srcRepOld, amount, 'ERC721Checkpointable::_moveDelegates: amount underflows');
                _writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);
            }

            if (dstRep != address(0)) {
                uint32 dstRepNum = numCheckpoints[dstRep];
                uint96 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;
                uint96 dstRepNew = add96(dstRepOld, amount, 'ERC721Checkpointable::_moveDelegates: amount overflows');
                _writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);
            }
        }
    }

    function _writeCheckpoint(
        address delegatee,
        uint32 nCheckpoints,
        uint96 oldVotes,
        uint96 newVotes
    ) internal {
        uint32 blockNumber = safe32(
            block.number,
            'ERC721Checkpointable::_writeCheckpoint: block number exceeds 32 bits'
        );

        if (nCheckpoints > 0 && checkpoints[delegatee][nCheckpoints - 1].fromBlock == blockNumber) {
            checkpoints[delegatee][nCheckpoints - 1].votes = newVotes;
        } else {
            checkpoints[delegatee][nCheckpoints] = Checkpoint(blockNumber, newVotes);
            numCheckpoints[delegatee] = nCheckpoints + 1;
        }

        emit DelegateVotesChanged(delegatee, oldVotes, newVotes);
    }

    function safe32(uint256 n, string memory errorMessage) internal pure returns (uint32) {
        require(n < 2**32, errorMessage);
        return uint32(n);
    }

    function safe96(uint256 n, string memory errorMessage) internal pure returns (uint96) {
        require(n < 2**96, errorMessage);
        return uint96(n);
    }

    function add96(
        uint96 a,
        uint96 b,
        string memory errorMessage
    ) internal pure returns (uint96) {
        uint96 c = a + b;
        require(c >= a, errorMessage);
        return c;
    }

    function sub96(
        uint96 a,
        uint96 b,
        string memory errorMessage
    ) internal pure returns (uint96) {
        require(b <= a, errorMessage);
        return a - b;
    }

    function getChainId() internal view returns (uint256) {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        return chainId;
    }
}

library Base64 {
    bytes internal constant TABLE =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// @notice Encodes some bytes to the base64 representation
    function encode(bytes memory data) internal pure returns (string memory) {
        uint256 len = data.length;
        if (len == 0) return "";

        // multiply by 4/3 rounded up
        uint256 encodedLen = 4 * ((len + 2) / 3);

        // Add some extra buffer at the end
        bytes memory result = new bytes(encodedLen + 32);

        bytes memory table = TABLE;

        assembly {
            let tablePtr := add(table, 1)
            let resultPtr := add(result, 32)

            for {
                let i := 0
            } lt(i, len) {

            } {
                i := add(i, 3)
                let input := and(mload(add(data, i)), 0xffffff)

                let out := mload(add(tablePtr, and(shr(18, input), 0x3F)))
                out := shl(8, out)
                out := add(
                    out,
                    and(mload(add(tablePtr, and(shr(12, input), 0x3F))), 0xFF)
                )
                out := shl(8, out)
                out := add(
                    out,
                    and(mload(add(tablePtr, and(shr(6, input), 0x3F))), 0xFF)
                )
                out := shl(8, out)
                out := add(
                    out,
                    and(mload(add(tablePtr, and(input, 0x3F))), 0xFF)
                )
                out := shl(224, out)

                mstore(resultPtr, out)

                resultPtr := add(resultPtr, 4)
            }

            switch mod(len, 3)
            case 1 {
                mstore(sub(resultPtr, 2), shl(240, 0x3d3d))
            }
            case 2 {
                mstore(sub(resultPtr, 1), shl(248, 0x3d))
            }

            mstore(result, encodedLen)
        }

        return string(result);
    }
}

contract TripleALoot is ERC721Checkpointable, ReentrancyGuard, Ownable {
    string[] private backgrounds = [
      '<rect width="100%" height="100%" fill="#fff"/>',
      '<rect width="100%" height="100%" fill="#f00"/>',
      '<rect width="100%" height="100%" fill="#0f0"/>',
      '<rect width="100%" height="100%" fill="#00f"/>',
      '<rect width="100%" height="100%" fill="#ff0"/>',
      '<rect width="100%" height="100%" fill="#0ff"/>'
    ];

    string[] private backgroundTextures = [
      '<text x="0" y="90" font-size="6">bgtxt-1</text>',
      '<text x="10" y="80" font-size="6">bgtxt-2</text>',
      '<text x="20" y="70" font-size="6">bgtxt-3</text>',
      '<text x="30" y="60" font-size="6">bgtxt-4</text>',
      '<text x="40" y="50" font-size="6">bgtxt-5</text>'
    ];

    string[] private letterBackdrops = [
      '<text x="50" y="90" font-size="6">ltrshdw-1</text>',
      '<text x="60" y="80" font-size="6">ltrshdw-2</text>',
      '<text x="70" y="70" font-size="6">ltrshdw-3</text>',
      '<text x="80" y="60" font-size="6">ltrshdw-4</text>',
      '<text x="90" y="50" font-size="6">ltrshdw-5</text>'
    ];

    string[] private letters = [
      '<text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-size="36">A</text>',
      '<text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-size="36">A</text>',
      '<text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-size="36">a</text>',
      '<text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-size="36">A</text>',
      '<text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-size="36">a</text>'
    ];

    string[] private letterTextures = [
      '<text fill="#666" x="30" y="60" font-size="16">1</text>',
      '<text fill="#666" x="40" y="50" font-size="16">2</text>',
      '<text fill="#666" x="50" y="40" font-size="16">3</text>',
      '<text fill="#666" x="60" y="30" font-size="16">4</text>',
      '<text fill="#666" x="70" y="20" font-size="16">5</text>'
    ];

    string[] private decorations = [
      '<text fill="#666" x="0" y="40" font-size="6">1</text>',
      '',
      '<text fill="#666" x="10" y="30" font-size="6">2</text>',
      '',
      '',
      '',
      '',
      '',
      '<text fill="#666" x="20" y="20" font-size="6">3</text>',
      '<text fill="#666" x="30" y="10" font-size="6">4</text>'
    ];

    string[] private specialItems = [
      '',
      '',
      '',
      '',
      '',
      '',
      '',
      '',
      '',
      '',
      '',
      '',
      '',
      '<text fill="#666" x="90" y="90" font-size="6">XOXO</text>',
      '',
      ''
    ];

    function random(string memory input) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(input)));
    }

    function getCredits(uint256 tokenId) public view returns (string memory) {
        return string(abi.encodePacked("<!--\nCREDITS\nTOKEN: ", tokenId, "\n-->"));
    }

    function getBackground(uint256 tokenId) public view returns (string memory) {
        return pluck(tokenId, "BACKGROUND", backgrounds);
    }

    function getBackgroundTexture(uint256 tokenId) public view returns (string memory) {
        return pluck(tokenId, "BACKGROUND-TEXTURE", backgroundTextures);
    }

    function getLetterBackdrop(uint256 tokenId) public view returns (string memory) {
        return pluck(tokenId, "LETTER-BACKDROP", letterBackdrops);
    }

    function getLetter(uint256 tokenId) public view returns (string memory) {
        return pluck(tokenId, "LETTER", letters);
    }

    function getLetterTexture(uint256 tokenId) public view returns (string memory) {
        return pluck(tokenId, "LETTER-TEXTURE", letterTextures);
    }

    function getDecoration(uint256 tokenId) public view returns (string memory) {
        return pluck(tokenId, "DECORATION", decorations);
    }

    function getSpecialItem(uint256 tokenId) public view returns (string memory) {
        return pluck(tokenId, "SPECIAL-ITEM", specialItems);
    }

    function pluck(
        uint256 tokenId,
        string memory keyPrefix,
        string[] memory sourceArray
    ) internal view returns (string memory) {
        uint256 rand = random(
            string(abi.encodePacked(keyPrefix, toString(tokenId)))
        );
        string memory output = sourceArray[rand % sourceArray.length];
        // uint256 greatness = rand % 21;
        // if (greatness > 14) {
        //     output = string(
        //         abi.encodePacked(output, " ", suffixes[rand % suffixes.length])
        //     );
        // }
        // if (greatness >= 19) {
        //     string[2] memory name;
        //     name[0] = namePrefixes[rand % namePrefixes.length];
        //     name[1] = nameSuffixes[rand % nameSuffixes.length];
        //     if (greatness == 19) {
        //         output = string(
        //             abi.encodePacked('"', name[0], " ", name[1], '" ', output)
        //         );
        //     } else {
        //         output = string(
        //             abi.encodePacked(
        //                 '"',
        //                 name[0],
        //                 " ",
        //                 name[1],
        //                 '" ',
        //                 output,
        //                 " +1"
        //             )
        //         );
        //     }
        // }
        return output;
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override
        returns (string memory)
    {
        string[17] memory parts;
        parts[
            0
        ] = '<svg xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMinYMin meet" viewBox="0 0 350 350">';
        parts[1] = getCredits(tokenId);
        parts[2] = getBackground(tokenId);
        parts[3] = getBackgroundTexture(tokenId);
        parts[4] = getLetterBackdrop(tokenId);
        parts[5] = getLetter(tokenId);
        parts[6] = getLetterTexture(tokenId);
        parts[7] = getDecoration(tokenId);
        parts[8] = getSpecialItem(tokenId);
        parts[9] = '</svg>';

        string memory output = string(
            abi.encodePacked(
                parts[0],
                parts[1],
                parts[2],
                parts[3],
                parts[4]
            )
        );
        output = string(
            abi.encodePacked(
                output,
                parts[5],
                parts[6],
                parts[7],
                parts[8],
                parts[9]
            )
        );

        string memory json = Base64.encode(
            bytes(
                string(
                    abi.encodePacked(
                        '{"name": "Letter #',
                        toString(tokenId),
                        '", "description": "~DESCRIPTION~", "image": "data:image/svg+xml;base64,',
                        Base64.encode(bytes(output)),
                        '"}'
                    )
                )
            )
        );
        output = string(
            abi.encodePacked("data:application/json;base64,", json)
        );

        return output;
    }

    function claim(uint256 tokenId) public nonReentrant {
        //CHANGE: limit
        require(tokenId > 0 && tokenId < 8001, "Token ID invalid");
        _safeMint(_msgSender(), tokenId);
    }

    function toString(uint256 value) internal pure returns (string memory) {
        // Inspired by OraclizeAPI's implementation - MIT license
        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol

        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    constructor() ERC721("Triple A", "AAA") Ownable() {}
}