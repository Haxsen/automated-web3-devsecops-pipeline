// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {SecureVault} from "../src/SecureVault.sol";
import {MockERC20} from "./mocks/Tokens.sol";
import {VaultHandler} from "./handlers/VaultHandler.sol";

/// @notice Stateful invariant tests: properties that must hold after *any* sequence of handler calls.
contract SecureVaultInvariantTest is Test {
    uint256 internal constant LIMIT = 1e29;

    MockERC20 internal token;
    SecureVault internal vault;
    VaultHandler internal handler;
    address internal admin = makeAddr("admin");

    function setUp() public {
        token = new MockERC20();
        vault = new SecureVault(token, admin, LIMIT);
        handler = new VaultHandler(vault, token, admin);

        bytes4[] memory selectors = new bytes4[](6);
        selectors[0] = VaultHandler.deposit.selector;
        selectors[1] = VaultHandler.withdraw.selector;
        selectors[2] = VaultHandler.donate.selector;
        selectors[3] = VaultHandler.rescueSurplus.selector;
        selectors[4] = VaultHandler.warp.selector;
        selectors[5] = VaultHandler.togglePause.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    /// @dev Solvency: the vault always holds at least what it owes.
    function invariant_Solvent() public view {
        assertGe(token.balanceOf(address(vault)), vault.totalDeposits());
    }

    /// @dev Accounting: totalDeposits is exactly the sum of every user's balance.
    function invariant_TotalDepositsEqualsSumOfBalances() public view {
        uint256 sum;
        for (uint256 i = 0; i < handler.actorCount(); i++) {
            sum += vault.balanceOf(handler.actors(i));
        }
        assertEq(sum, vault.totalDeposits());
    }

    /// @dev Conservation: deposits minus withdrawals is what the vault owes, no value created or lost.
    function invariant_ValueConserved() public view {
        assertEq(handler.ghostDeposited() - handler.ghostWithdrawn(), vault.totalDeposits());
        assertEq(
            token.balanceOf(address(vault)),
            vault.totalDeposits() + handler.ghostDonated() - handler.ghostRescued(),
            "surplus must equal donations not yet rescued"
        );
    }

    /// @dev Circuit breaker: outflow inside a window can never exceed the configured cap.
    function invariant_OutflowWithinRateLimit() public view {
        assertLe(vault.withdrawnInWindow(), vault.withdrawLimitPerWindow());
    }
}
