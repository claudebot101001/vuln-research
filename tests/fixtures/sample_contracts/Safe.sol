// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title SafeVault - a secure vault for comparison
contract SafeVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Reentrancy");
        locked = true;
        _;
        locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // Correct: state update before external call + reentrancy guard
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // Correct: access control present
    function emergencyWithdraw(address to, uint256 amount) external onlyOwner {
        (bool success, ) = to.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
