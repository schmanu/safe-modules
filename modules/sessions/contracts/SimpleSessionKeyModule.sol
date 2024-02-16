// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@account-abstraction/contracts/core/Helpers.sol";
import {ISafe} from "./interfaces/Safe.sol";

/**
 * @title SimpleSessionKeyManager
 *
 * Enables session management for a Safe.
 * Sessions are created off-chain by signing a MerkleRoot with the Safe using EIP-1271. 
 * Every UserOperation contains data to proof that the UserOperation was executed by a valid session.
 *
 */
contract SimpleSessionKeyManager is IAccount {
  bytes4 constant internal MAGICVALUE = 0x1626ba7e;
  public address safeAddress;

  constructor(address safe) {
    safeAddress = safe;
  }
  
    /**
     * @notice Validates the call is initiated by the entry point.
     */
    modifier onlySupportedEntryPoint() {
        require(_msgSender() == SUPPORTED_ENTRYPOINT, "Unsupported entry point");
        _;
    }

    /**
     * @notice Validates a user operation provided by the entry point.
     * @inheritdoc IAccount
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 _userOpHash,
        uint256 missingAccountFunds
    ) external onlySupportedEntryPoint returns (uint256 validationData) {
        (bytes memory moduleSignature, ) = abi.decode(
            userOp.signature,
            (bytes, address)
        );
        (
            uint48 validUntil,
            uint48 validAfter,
            bytes32[] memory merkleProof,
            bytes32 merkleRoot,
            bytes memory merkleRootSignature,
            address sessionKey,
            bytes memory sessionKeySignature,
        ) = abi.decode(
                moduleSignature,
                (uint48, uint48, address, bytes32[], bytes32, bytes, bytes, bytes)
            );

        // Check that the call goes to the same Safe
        // We check the execution function signature to make sure the entry point can't call any other function
        // and make sure the execution of the user operation is handled by the module
        require(
            this.executeUserOp.selector == bytes4(userOp.callData)
            "Unsupported execution function id"
        );


        validationData = _packValidationData(validateSessionKey(
            validUntil,
            validAfter,
            safeAddress,
            merkleProof,
            merkleRoot,
            merkleRootSignature,
            _userOpHash,
            sessionKey,
            sessionKeySignature
        ), validUntil, validAfter);

        // We trust the entry point to set the correct prefund value, based on the operation params
        // We need to perform this even if the signature is not valid, else the simulation function of the entry point will not work.
        if (missingAccountFunds != 0) {
            // We intentionally ignore errors in paying the missing account funds, as the entry point is responsible for
            // verifying the prefund has been paid. This behaviour matches the reference base account implementation.
            ISafe(safeAddress).execTransactionFromModule(SUPPORTED_ENTRYPOINT, missingAccountFunds, "", 0);
        }
    }




    /**
     * @dev validates that Session Key + parameters are enabled
     * by being included into the merkle tree
     * @param validUntil timestamp when the session key expires
     * @param validAfter timestamp when the session key becomes valid
     * @param merkleProof merkle proof for the leaf which represents this session key + params
     * @param merkleRoot merkle root 
     * @dev if doesn't revert, session key is considered valid
     */
    function validateSessionKey(
        uint48 validUntil,
        uint48 validAfter,
        bytes32[] memory merkleProof
        bytes32 merkleRoot,
        bytes memory merkleRootSignature,
        bytes32 _userOpHash,
        address sessionKey,
        bytes memory sessionKeySignature,

    ) internal view returns (bool) {
        // First check if the Safe actually signed the merkleRoot
        if (ISafe(safeAddress).isValidSignature(merkleRoot, merkleRootSignature) != MAGICVALUE) {
            return false
        }

        // Then check if the merkle proof with the sender address is valid
        bytes32 leaf = keccak256(
            abi.encodePacked(
                validUntil,
                validAfter,
                sessionKey,
            )
        );
        if (
            !MerkleProof.verify(merkleProof, sessionKeyStorage.merkleRoot, leaf)
        ) {
            return false
        }

        // Lastly check if the privateKey from the session signed the userOperation.

        
        return ECDSA.recover(
                ECDSA.toEthSignedMessageHash(_userOpHash),
                _sessionKeySignature
            ) == sessionKey
    }

    /**
     * @notice Executes a user operation provided by the entry point.
     * @param to Destination address of the user operation.
     * @param value Ether value of the user operation.
     * @param data Data payload of the user operation.
     * @param operation Operation type of the user operation.
     */
    function executeUserOp(address safe, address to, uint256 value, bytes memory data, uint8 operation) external onlySupportedEntryPoint {
        require(ISafe(msg.sender).execTransactionFromModule(to, value, data, operation), "Execution failed");
    }

    /**
     * @dev isValidSignature
     * @param _dataHash
     * @param _signature
     * @return always returns magic value such that the signature is always valid
     */
    function isValidSignature(
        bytes32 _dataHash,
        bytes memory _signature
    ) public view override returns (bytes4) {
        (_dataHash, _signature);
         return MAGICVALUE;
    }
}