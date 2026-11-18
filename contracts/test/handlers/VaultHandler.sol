// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";

import {SecureVault} from "../../src/SecureVault.sol";
import {MockERC20} from "../mocks/Tokens.sol";

/// @notice Drives the vault through random but *valid-shaped* sequences of user and admin actions
///         while keeping ghost accounting the invariants are checked against.
contract VaultHandler is CommonBase, StdCheats, StdUtils {
    SecureVault public immutable vault;
    MockERC20 public immutable token;
    address public immutable admin;

    address[] public actors;

    // Ghost variables: an independent model of what *should* be true.
    uint256 public ghostDeposited;
    uint256 public ghostWithdrawn;
    uint256 public ghostDonated;
    uint256 public ghostRescued;
    mapping(bytes32 action => uint256 count) public calls;

    constructor(SecureVault vault_, MockERC20 token_, address admin_) {
        vault = vault_;
        token = token_;
        admin = admin_;
        for (uint256 i = 0; i < 5; i++) {
            actors.push(makeAddr(string.concat("actor", vm.toString(i))));
        }
    }

    function actorCount() external view returns (uint256) {
        return actors.length;
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    function deposit(uint256 actorSeed, uint256 amount) external {
        if (vault.paused()) return;
        address actor = _actor(actorSeed);
        amount = bound(amount, 1, 1e30);

        token.mint(actor, amount);
        vm.startPrank(actor);
        token.approve(address(vault), amount);
        vault.deposit(amount);
        vm.stopPrank();

        ghostDeposited += amount;
        calls["deposit"]++;
    }

    function withdraw(uint256 actorSeed, uint256 amount) external {
        if (vault.paused()) return;
        address actor = _actor(actorSeed);
        uint256 maxAmount = vault.balanceOf(actor);
        uint256 remaining = vault.remainingWithdrawLimit();
        if (remaining < maxAmount) maxAmount = remaining;
        if (maxAmount == 0) return;
        amount = bound(amount, 1, maxAmount);

        vm.prank(actor);
        vault.withdraw(amount, actor);

        ghostWithdrawn += amount;
        calls["withdraw"]++;
    }

    /// @dev Tokens sent directly to the vault (airdrops, mistakes) must never be credited to anyone.
    function donate(uint256 amount) external {
        amount = bound(amount, 1, 1e24);
        token.mint(address(vault), amount);
        ghostDonated += amount;
        calls["donate"]++;
    }

    function rescueSurplus(uint256 amount) external {
        uint256 surplus = token.balanceOf(address(vault)) - vault.totalDeposits();
        if (surplus == 0) return;
        amount = bound(amount, 1, surplus);

        vm.prank(admin);
        vault.rescue(token, admin, amount);

        ghostRescued += amount;
        calls["rescue"]++;
    }

    function warp(uint256 secondsForward) external {
        secondsForward = bound(secondsForward, 1 minutes, 2 days);
        vm.warp(block.timestamp + secondsForward);
        calls["warp"]++;
    }

    function togglePause() external {
        vm.startPrank(admin);
        if (vault.paused()) vault.unpause();
        else vault.pause();
        vm.stopPrank();
        calls["togglePause"]++;
    }
}
