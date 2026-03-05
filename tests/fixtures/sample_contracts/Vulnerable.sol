// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// Vulnerable contract with multiple known bug patterns for integration testing.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title VulnerableVault - a vault with intentional vulnerabilities
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool private locked;

    constructor() {
        owner = msg.sender;
    }

    // BUG 1: Reentrancy - external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call BEFORE state update - classic reentrancy
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update AFTER external call
        balances[msg.sender] -= amount;
    }

    // BUG 2: Missing access control - anyone can drain
    function emergencyWithdraw(address token, address to, uint256 amount) external {
        // No onlyOwner modifier!
        IERC20(token).transfer(to, amount);
    }

    // BUG 3: Unchecked return value
    function transferTokens(address token, address to, uint256 amount) external {
        // Return value of transfer not checked
        IERC20(token).transfer(to, amount);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}

/// @title VulnerableOracle - price oracle with manipulation risk
contract VulnerableOracle {
    address public pair;

    constructor(address _pair) {
        pair = _pair;
    }

    // BUG 4: Spot price from reserves - manipulable via flash loan
    function getPrice() external view returns (uint256) {
        // Using getReserves for spot price - easily manipulable
        (uint112 reserve0, uint112 reserve1, ) = IUniswapV2Pair(pair).getReserves();
        return uint256(reserve0) * 1e18 / uint256(reserve1);
    }
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

/// @title VulnerableProxy - proxy with storage collision risk
contract VulnerableProxy {
    address public implementation;
    address public admin;

    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
    }

    // BUG 5: delegatecall with variable address
    function upgradeAndCall(address newImpl, bytes calldata data) external {
        implementation = newImpl;
        (bool success, ) = newImpl.delegatecall(data);
        require(success);
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
