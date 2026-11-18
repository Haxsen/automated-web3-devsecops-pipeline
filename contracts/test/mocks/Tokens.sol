// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Plain mintable ERC20 for tests.
contract MockERC20 is ERC20 {
    constructor() ERC20("Mock Token", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @notice Deflationary token that burns 1% of every transfer, to prove the vault credits what it received.
contract FeeOnTransferToken is ERC20 {
    uint256 public constant FEE_BPS = 100;

    constructor() ERC20("Fee Token", "FEE") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0)) {
            uint256 fee = (value * FEE_BPS) / 10_000;
            super._update(from, address(0), fee);
            value -= fee;
        }
        super._update(from, to, value);
    }
}

/// @notice Malicious token that re-enters a target during transfers, emulating ERC777-style hooks.
contract ReentrantToken is ERC20 {
    address public target;
    bytes public payload;
    bool private _armed;

    constructor() ERC20("Reentrant Token", "EVIL") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function arm(address target_, bytes calldata payload_) external {
        target = target_;
        payload = payload_;
        _armed = true;
    }

    function _update(address from, address to, uint256 value) internal override {
        super._update(from, to, value);
        if (_armed) {
            _armed = false;
            (bool ok, bytes memory ret) = target.call(payload);
            if (!ok) {
                // Bubble up the revert reason so tests can assert on the exact guard that fired.
                assembly ("memory-safe") {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
        }
    }
}
