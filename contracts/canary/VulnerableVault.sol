// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// =================================================================================================
//  INTENTIONALLY VULNERABLE. DO NOT DEPLOY.
//
//  This contract is a *scanner canary*: a known-bad control sample that the pipeline feeds to
//  Slither on every run. The pipeline asserts that the expected detectors fire. If a tool upgrade,
//  config change or broken install silently stops detecting these bugs, the canary job fails,
//  instead of the security gate quietly turning green on real code.
//
//  It is excluded from the main Slither gate via `filter_paths` in slither.config.json and is only
//  compiled by Foundry because test/canary/ReentrancyExploit.t.sol imports it to prove the
//  exploit is real.
// =================================================================================================

contract VulnerableVault {
    mapping(address account => uint256 amount) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @dev BUG (SWC-107 reentrancy): external call happens before the balance is zeroed.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] = 0;
    }

    /// @dev BUG (SWC-115): authorisation via tx.origin can be phished through an intermediate contract.
    function emergencyWithdraw(address payable to) external {
        require(tx.origin == owner, "not owner");
        to.transfer(address(this).balance);
    }
}
