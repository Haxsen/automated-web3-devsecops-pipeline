// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title SecureVault
/// @notice Single-asset custody vault used as the reference target of the DevSecOps pipeline.
/// @dev Defence-in-depth controls:
///      - Role-based access control with separation of duties (pausers can stop, only admins can resume).
///      - Emergency circuit breaker (`Pausable`) that freezes deposits and withdrawals during an incident.
///      - Reentrancy guard on every state-changing external entry point, plus checks-effects-interactions.
///      - Balance-delta accounting so fee-on-transfer / deflationary tokens cannot inflate credited balances.
///      - Rolling outflow rate limit: caps how much value can leave per window, bounding the blast radius
///        of a compromised account or an undiscovered logic bug.
///      - Rescue path that can never touch user funds (only surplus above `totalDeposits`).
contract SecureVault is AccessControl, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice Can trigger the emergency pause (e.g. an incident-response bot or guardian multisig).
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    /// @notice Can tune the outflow rate limit.
    bytes32 public constant LIMIT_ADMIN_ROLE = keccak256("LIMIT_ADMIN_ROLE");

    /// @notice Length of one rate-limit window.
    uint256 public constant WINDOW = 1 days;

    /// @notice The only token this vault custodies.
    IERC20 public immutable asset;

    /// @notice Sum of all user balances. Invariant: `asset.balanceOf(this) >= totalDeposits`.
    uint256 public totalDeposits;
    /// @notice Per-account credited balance.
    mapping(address account => uint256 amount) public balanceOf;

    /// @notice Maximum amount that may be withdrawn (by all users combined) within one window.
    uint256 public withdrawLimitPerWindow;
    /// @notice Start timestamp of the current rate-limit window.
    uint256 public windowStart;
    /// @notice Amount withdrawn so far in the current window.
    uint256 public withdrawnInWindow;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, address indexed to, uint256 amount);
    event WithdrawLimitUpdated(uint256 previousLimit, uint256 newLimit);
    event SurplusRescued(address indexed token, address indexed to, uint256 amount);

    error ZeroAddress();
    error ZeroAmount();
    error InsufficientBalance(uint256 requested, uint256 available);
    error WithdrawLimitExceeded(uint256 requested, uint256 remaining);
    error RescueExceedsSurplus(uint256 requested, uint256 surplus);

    /// @param asset_ Token held by the vault.
    /// @param admin Initial admin; should be a timelock or multisig in production, never an EOA.
    /// @param withdrawLimit_ Initial outflow cap per `WINDOW`.
    constructor(IERC20 asset_, address admin, uint256 withdrawLimit_) {
        if (address(asset_) == address(0) || admin == address(0)) revert ZeroAddress();

        asset = asset_;
        withdrawLimitPerWindow = withdrawLimit_;
        windowStart = block.timestamp;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(LIMIT_ADMIN_ROLE, admin);

        emit WithdrawLimitUpdated(0, withdrawLimit_);
    }

    // ---------------------------------------------------------------------------------------------
    // User actions
    // ---------------------------------------------------------------------------------------------

    /// @notice Deposit `amount` of `asset`. The caller is credited with what the vault actually received.
    /// @return received Amount credited to the caller.
    function deposit(uint256 amount) external nonReentrant whenNotPaused returns (uint256 received) {
        if (amount == 0) revert ZeroAmount();

        // Balance-delta accounting: credit what arrived, not what was requested. The state update after the
        // transfer is safe because the function is `nonReentrant` and the token is trusted to be the asset.
        uint256 balanceBefore = asset.balanceOf(address(this));
        asset.safeTransferFrom(msg.sender, address(this), amount);
        received = asset.balanceOf(address(this)) - balanceBefore;
        // TRIAGED (Slither `incorrect-equality`): not a griefable balance match. Donations can only make
        // `received` larger, never zero; this only rejects tokens that charge a 100% transfer fee.
        // slither-disable-next-line incorrect-equality
        if (received == 0) revert ZeroAmount();

        balanceOf[msg.sender] += received;
        totalDeposits += received;

        emit Deposited(msg.sender, received);
    }

    /// @notice Withdraw `amount` of the caller's balance to `to`, subject to the outflow rate limit.
    function withdraw(uint256 amount, address to) external nonReentrant whenNotPaused {
        if (amount == 0) revert ZeroAmount();
        if (to == address(0)) revert ZeroAddress();

        uint256 balance = balanceOf[msg.sender];
        if (amount > balance) revert InsufficientBalance(amount, balance);

        _consumeWithdrawLimit(amount);

        // Effects before interactions.
        unchecked {
            balanceOf[msg.sender] = balance - amount;
        }
        totalDeposits -= amount;

        emit Withdrawn(msg.sender, to, amount);

        asset.safeTransfer(to, amount);
    }

    // ---------------------------------------------------------------------------------------------
    // Privileged actions
    // ---------------------------------------------------------------------------------------------

    /// @notice Emergency stop. Callable by any pauser.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Resume operations. Deliberately restricted to the admin (separation of duties).
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Update the per-window outflow cap.
    function setWithdrawLimit(uint256 newLimit) external onlyRole(LIMIT_ADMIN_ROLE) {
        uint256 previousLimit = withdrawLimitPerWindow;
        withdrawLimitPerWindow = newLimit;
        emit WithdrawLimitUpdated(previousLimit, newLimit);
    }

    /// @notice Recover tokens sent to the vault by mistake. User funds are untouchable: for the vault asset,
    ///         only the surplus above `totalDeposits` can be recovered.
    function rescue(IERC20 token, address to, uint256 amount) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();

        if (address(token) == address(asset)) {
            uint256 surplus = asset.balanceOf(address(this)) - totalDeposits;
            if (amount > surplus) revert RescueExceedsSurplus(amount, surplus);
        }

        emit SurplusRescued(address(token), to, amount);

        token.safeTransfer(to, amount);
    }

    // ---------------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------------

    /// @notice Amount that can still be withdrawn in the current window.
    function remainingWithdrawLimit() public view returns (uint256) {
        if (_windowElapsed()) return withdrawLimitPerWindow;
        return _remainingInCurrentWindow();
    }

    // ---------------------------------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------------------------------

    function _consumeWithdrawLimit(uint256 amount) private {
        if (_windowElapsed()) {
            windowStart = block.timestamp;
            withdrawnInWindow = 0;
        }

        uint256 remaining = _remainingInCurrentWindow();
        if (amount > remaining) revert WithdrawLimitExceeded(amount, remaining);

        withdrawnInWindow += amount;
    }

    /// @dev Saturates at zero: the admin may lower the limit below what was already withdrawn this window.
    function _remainingInCurrentWindow() private view returns (uint256) {
        return withdrawLimitPerWindow > withdrawnInWindow ? withdrawLimitPerWindow - withdrawnInWindow : 0;
    }

    /// @dev TRIAGED (Slither `timestamp`, forge-lint `block-timestamp`): timestamp dependence is intentional
    ///      and benign. Validators can skew time by seconds; the window is a full day, so the worst case is
    ///      a window rolling over a few seconds early.
    // forge-lint: disable-next-item(block-timestamp)
    function _windowElapsed() private view returns (bool) {
        // slither-disable-next-line timestamp
        return block.timestamp >= windowStart + WINDOW;
    }
}
