// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract TokenHolder {
    address public owner;
    IERC20 public token;

    constructor(address _token) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    function withdrawToken(uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        token.transfer(msg.sender, amount);
    }
}

contract TokenVault is TokenHolder {
    mapping(address => uint256) public deposits;
    uint256 public totalLocked;

    constructor(address _token) TokenHolder(_token) {}

    function depositToken(uint256 amount) external {
        deposits[msg.sender] += amount;
        totalLocked += amount;
    }

    function withdrawDeposit(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient");
        deposits[msg.sender] -= amount;
        totalLocked -= amount;
        token.transfer(msg.sender, amount);
    }
}
