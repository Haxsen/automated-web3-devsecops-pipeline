// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {SecureVault} from "../src/SecureVault.sol";

/// @notice Deploys SecureVault.
/// @dev The signer is supplied on the command line, never via a private key in env or files.
///      In CI the deployer key lives in AWS KMS (secp256k1, see infra/terraform/kms.tf):
///
///        forge script script/Deploy.s.sol --rpc-url "$RPC_URL" --broadcast --aws --sender "$DEPLOYER_ADDRESS"
///
///      Required env: VAULT_ASSET, VAULT_ADMIN, VAULT_WITHDRAW_LIMIT.
contract Deploy is Script {
    function run() external returns (SecureVault vault) {
        IERC20 asset = IERC20(vm.envAddress("VAULT_ASSET"));
        address admin = vm.envAddress("VAULT_ADMIN");
        uint256 withdrawLimit = vm.envUint("VAULT_WITHDRAW_LIMIT");

        require(address(asset).code.length > 0, "VAULT_ASSET is not a contract");
        require(admin.code.length > 0, "VAULT_ADMIN must be a multisig/timelock contract, not an EOA");

        vm.startBroadcast();
        vault = new SecureVault(asset, admin, withdrawLimit);
        vm.stopBroadcast();

        console2.log("SecureVault deployed at", address(vault));
    }
}
