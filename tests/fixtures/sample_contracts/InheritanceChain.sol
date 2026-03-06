// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Pausable {
    bool internal _paused;

    modifier whenNotPaused() {
        require(!_paused, "Paused");
        _;
    }
}

abstract contract AccessControl {
    mapping(address => bool) internal _admins;

    modifier onlyAdmin() {
        require(_admins[msg.sender], "Not admin");
        _;
    }
}

contract ManagedToken is Pausable, AccessControl {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    string public name;

    constructor(string memory _name) {
        name = _name;
        _admins[msg.sender] = true;
    }

    function mint(address to, uint256 amount) external onlyAdmin whenNotPaused {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function burn(address from, uint256 amount) external onlyAdmin {
        require(balanceOf[from] >= amount, "Insufficient");
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }
}
