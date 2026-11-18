// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {SecureVault} from "../src/SecureVault.sol";
import {MockERC20, FeeOnTransferToken, ReentrantToken} from "./mocks/Tokens.sol";

contract SecureVaultTest is Test {
    uint256 internal constant LIMIT = 1_000_000 ether;
    uint256 internal constant MAX_DEPOSIT = 1_000_000_000 ether;

    MockERC20 internal token;
    SecureVault internal vault;

    address internal admin = makeAddr("admin");
    address internal pauser = makeAddr("pauser");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        token = new MockERC20();
        vault = new SecureVault(token, admin, LIMIT);

        bytes32 pauserRole = vault.PAUSER_ROLE();
        vm.prank(admin);
        vault.grantRole(pauserRole, pauser);
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------

    function _deposit(address who, uint256 amount) internal {
        token.mint(who, amount);
        vm.startPrank(who);
        token.approve(address(vault), amount);
        vault.deposit(amount);
        vm.stopPrank();
    }

    // ---------------------------------------------------------------------------------------------
    // Deployment
    // ---------------------------------------------------------------------------------------------

    function test_Constructor_SetsRolesAndConfig() public view {
        assertEq(address(vault.asset()), address(token));
        assertEq(vault.withdrawLimitPerWindow(), LIMIT);
        assertTrue(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(vault.hasRole(vault.PAUSER_ROLE(), admin));
        assertTrue(vault.hasRole(vault.LIMIT_ADMIN_ROLE(), admin));
    }

    function test_RevertWhen_ConstructorGetsZeroAddress() public {
        vm.expectRevert(SecureVault.ZeroAddress.selector);
        new SecureVault(IERC20(address(0)), admin, LIMIT);

        vm.expectRevert(SecureVault.ZeroAddress.selector);
        new SecureVault(token, address(0), LIMIT);
    }

    // ---------------------------------------------------------------------------------------------
    // Deposits and withdrawals
    // ---------------------------------------------------------------------------------------------

    function testFuzz_DepositWithdrawRoundTrip(uint256 amount) public {
        amount = bound(amount, 1, LIMIT);

        _deposit(alice, amount);
        assertEq(vault.balanceOf(alice), amount);
        assertEq(vault.totalDeposits(), amount);

        vm.prank(alice);
        vault.withdraw(amount, alice);

        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.totalDeposits(), 0);
        assertEq(token.balanceOf(alice), amount);
        assertEq(token.balanceOf(address(vault)), 0);
    }

    function testFuzz_WithdrawToThirdParty(uint256 amount, address recipient) public {
        vm.assume(recipient != address(0) && recipient != address(vault));
        amount = bound(amount, 1, LIMIT);
        _deposit(alice, amount);

        uint256 before = token.balanceOf(recipient);
        vm.prank(alice);
        vault.withdraw(amount, recipient);

        assertEq(token.balanceOf(recipient) - before, amount);
    }

    function testFuzz_RevertWhen_WithdrawExceedsBalance(uint256 deposited, uint256 requested) public {
        deposited = bound(deposited, 1, MAX_DEPOSIT);
        requested = bound(requested, deposited + 1, type(uint256).max);
        _deposit(alice, deposited);

        vm.expectRevert(abi.encodeWithSelector(SecureVault.InsufficientBalance.selector, requested, deposited));
        vm.prank(alice);
        vault.withdraw(requested, alice);
    }

    function testFuzz_RevertWhen_WithdrawingSomeoneElsesFunds(uint256 amount) public {
        amount = bound(amount, 1, LIMIT);
        _deposit(alice, amount);

        vm.expectRevert(abi.encodeWithSelector(SecureVault.InsufficientBalance.selector, amount, 0));
        vm.prank(bob);
        vault.withdraw(amount, bob);
    }

    function test_RevertWhen_ZeroAmountOrZeroRecipient() public {
        vm.expectRevert(SecureVault.ZeroAmount.selector);
        vault.deposit(0);

        _deposit(alice, 1 ether);
        vm.startPrank(alice);
        vm.expectRevert(SecureVault.ZeroAmount.selector);
        vault.withdraw(0, alice);
        vm.expectRevert(SecureVault.ZeroAddress.selector);
        vault.withdraw(1 ether, address(0));
        vm.stopPrank();
    }

    /// @dev A token whose transferFrom reports success but moves nothing must not mint credit.
    function test_RevertWhen_TokenDeliversNothing() public {
        vm.mockCall(address(token), abi.encodeWithSelector(IERC20.transferFrom.selector), abi.encode(true));

        vm.expectRevert(SecureVault.ZeroAmount.selector);
        vm.prank(alice);
        vault.deposit(1 ether);

        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.totalDeposits(), 0);
    }

    function testFuzz_FeeOnTransferTokenCreditsOnlyWhatArrived(uint256 amount) public {
        amount = bound(amount, 100, MAX_DEPOSIT);
        FeeOnTransferToken feeToken = new FeeOnTransferToken();
        SecureVault feeVault = new SecureVault(feeToken, admin, type(uint256).max);

        feeToken.mint(alice, amount);
        vm.startPrank(alice);
        feeToken.approve(address(feeVault), amount);
        uint256 credited = feeVault.deposit(amount);
        vm.stopPrank();

        uint256 expected = amount - (amount * feeToken.FEE_BPS()) / 10_000;
        assertEq(credited, expected);
        assertEq(feeVault.balanceOf(alice), expected);
        assertEq(feeToken.balanceOf(address(feeVault)), feeVault.totalDeposits(), "vault must stay exactly solvent");
    }

    // ---------------------------------------------------------------------------------------------
    // Reentrancy
    // ---------------------------------------------------------------------------------------------

    /// @dev Contrast with test/canary/ReentrancyExploit.t.sol: the same attack class that drains
    ///      VulnerableVault is stopped here by the guard (and would be harmless anyway thanks to CEI).
    function test_RevertWhen_TokenHookReentersWithdraw() public {
        ReentrantToken evil = new ReentrantToken();
        SecureVault evilVault = new SecureVault(evil, admin, type(uint256).max);

        evil.mint(alice, 10 ether);
        vm.startPrank(alice);
        evil.approve(address(evilVault), 10 ether);
        evilVault.deposit(10 ether);
        vm.stopPrank();

        // When the vault pays out, the token calls back into withdraw() before the outer call returns.
        evil.arm(address(evilVault), abi.encodeCall(SecureVault.withdraw, (1 ether, alice)));

        vm.expectRevert(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        vm.prank(alice);
        evilVault.withdraw(1 ether, alice);

        assertEq(evilVault.balanceOf(alice), 10 ether, "state must be fully rolled back");
    }

    // ---------------------------------------------------------------------------------------------
    // Rate limit (circuit breaker)
    // ---------------------------------------------------------------------------------------------

    function testFuzz_RateLimitCapsOutflowPerWindow(uint256 first, uint256 second) public {
        _deposit(alice, 2 * LIMIT);
        first = bound(first, 1, LIMIT);
        second = bound(second, LIMIT - first + 1, 2 * LIMIT - first);

        vm.startPrank(alice);
        vault.withdraw(first, alice);
        vm.expectRevert(abi.encodeWithSelector(SecureVault.WithdrawLimitExceeded.selector, second, LIMIT - first));
        vault.withdraw(second, alice);
        vm.stopPrank();
    }

    function test_RateLimitResetsAfterWindow() public {
        _deposit(alice, 2 * LIMIT);

        vm.startPrank(alice);
        vault.withdraw(LIMIT, alice);
        assertEq(vault.remainingWithdrawLimit(), 0);

        vm.warp(block.timestamp + vault.WINDOW());
        assertEq(vault.remainingWithdrawLimit(), LIMIT);
        vault.withdraw(LIMIT, alice);
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 2 * LIMIT);
    }

    function test_LoweringLimitBelowUsageBlocksFurtherOutflow() public {
        _deposit(alice, LIMIT);
        vm.prank(alice);
        vault.withdraw(LIMIT / 2, alice);

        vm.prank(admin);
        vault.setWithdrawLimit(LIMIT / 4);
        assertEq(vault.remainingWithdrawLimit(), 0);

        vm.expectRevert(abi.encodeWithSelector(SecureVault.WithdrawLimitExceeded.selector, 1, 0));
        vm.prank(alice);
        vault.withdraw(1, alice);
    }

    function testFuzz_RevertWhen_NonLimitAdminSetsLimit(address caller, uint256 newLimit) public {
        vm.assume(caller != admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, caller, vault.LIMIT_ADMIN_ROLE()
            )
        );
        vm.prank(caller);
        vault.setWithdrawLimit(newLimit);
    }

    // ---------------------------------------------------------------------------------------------
    // Pause (incident response)
    // ---------------------------------------------------------------------------------------------

    function test_PauseFreezesDepositsAndWithdrawals() public {
        _deposit(alice, 1 ether);

        vm.prank(pauser);
        vault.pause();

        vm.startPrank(alice);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        vault.withdraw(1 ether, alice);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        vault.deposit(1 ether);
        vm.stopPrank();

        vm.prank(admin);
        vault.unpause();

        vm.prank(alice);
        vault.withdraw(1 ether, alice);
    }

    function test_RevertWhen_PauserTriesToUnpause() public {
        vm.prank(pauser);
        vault.pause();

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, pauser, vault.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(pauser);
        vault.unpause();
    }

    function testFuzz_RevertWhen_NonPauserPauses(address caller) public {
        vm.assume(caller != admin && caller != pauser);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, caller, vault.PAUSER_ROLE()
            )
        );
        vm.prank(caller);
        vault.pause();
    }

    // ---------------------------------------------------------------------------------------------
    // Rescue
    // ---------------------------------------------------------------------------------------------

    function testFuzz_RescueCanOnlyTakeSurplus(uint256 userFunds, uint256 donation, uint256 attempt) public {
        userFunds = bound(userFunds, 1, MAX_DEPOSIT);
        donation = bound(donation, 0, MAX_DEPOSIT);
        attempt = bound(attempt, donation + 1, donation + userFunds);

        _deposit(alice, userFunds);
        token.mint(address(vault), donation);

        vm.expectRevert(abi.encodeWithSelector(SecureVault.RescueExceedsSurplus.selector, attempt, donation));
        vm.prank(admin);
        vault.rescue(token, admin, attempt);

        if (donation > 0) {
            vm.prank(admin);
            vault.rescue(token, admin, donation);
        }
        assertEq(token.balanceOf(address(vault)), vault.totalDeposits(), "user funds untouched");
    }

    function test_RescueUnrelatedToken() public {
        MockERC20 stray = new MockERC20();
        stray.mint(address(vault), 5 ether);

        vm.prank(admin);
        vault.rescue(stray, bob, 5 ether);

        assertEq(stray.balanceOf(bob), 5 ether);
    }

    function test_RevertWhen_RescueToZeroAddressOrZeroAmount() public {
        token.mint(address(vault), 1 ether);

        vm.startPrank(admin);
        vm.expectRevert(SecureVault.ZeroAddress.selector);
        vault.rescue(token, address(0), 1 ether);
        vm.expectRevert(SecureVault.ZeroAmount.selector);
        vault.rescue(token, admin, 0);
        vm.stopPrank();
    }

    function testFuzz_RevertWhen_NonAdminRescues(address caller) public {
        vm.assume(caller != admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, caller, vault.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(caller);
        vault.rescue(token, caller, 1);
    }
}
