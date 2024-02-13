// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "../interfaces/ILido.sol";

/**
 * @title DegaISPO
 * @author DEGA
 * @notice This contract is designed to manage an Initial Stake Pool Offering (ISPO). Users can deposit their tokens into the contract and earn rewards.
 * The contract features role-based access control, allowing different roles such as the Reward Scheduler and the Pauser to perform specific actions.
 * It also includes an emergency withdrawal mechanism for situations where immediate access to funds is required.
 * @dev The contract uses OpenZeppelin libraries for access control, pausability, and reentrancy protection. It also interfaces with a Lido contract for handling staking and share calculations.
 * The contract keeps track of user balances, and shares, and emits events for deposit, withdrawal, and reward assignment.
 * @dev The contract is designed to be self-managing, automatically calculating and assigning rewards based on the amount of tokens deposited by each user and the time since the last reward assignment.
 * @dev The contract's state, including the total amount of tokens deposited and the rewards per share, is stored in public state variables for transparency and ease of auditing.
 * Invariant: User should be able to deposit and receive in withdrawal the exact amount during normal operation. 
 * Exception would be a loss of capital on Lido protocol.
 */
contract DegaISPO is AccessControl, Pausable, ReentrancyGuard {
    // Roles
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // State variables
    uint256 public maxTotalDeposit;
    uint256 public accumulatedScaledBalance;
    uint256 public totalSharesDeposited;
    uint256 public poolETHSize;
    uint256 public degaTreasuryShares;

    // Structs definitions
    struct RewardCalculations {
        uint256 sharesToAssignRewards;
    }

    struct UserInfo {
        uint256 amount;
        uint256 shares;
    }

    // Storage
    mapping(address => UserInfo) public userInfo;
    uint256 public lastRewardAssignmentTimestamp;

    ILido public lidoContract;

    error ZeroAddress();
    error ZeroAmount();
    error InsufficientShares();
    error MaxTotalCanNotBeLessThanPoolEthSize();
    error MaxTotalDepositExceeded();
    error DepositFailed();
    error NotEnoughBalance();
    error NothingToWithdraw();

    // add events
    event Deposit(address indexed user, uint256 amount, uint256 shares);
    event Withdraw(address indexed user, uint256 amount, uint256 shares);
    event AssignRewards(
        uint256 sharesToAssignRewards, uint256 totalSharesDeposited, uint256 timestamp
    );
    event MaxTotalDepositUpdated(uint256 maxTotalDeposit);
    event EmergencyWithdraw(address indexed user, uint256 amount, uint256 shares);

    /**
     * @dev Contract constructor.
     * @param _admin The address of the contract administrator.
     * @param _lidoAddress The address of the Lido contract.
     * @param _maxTotalDeposit The maximum total deposit allowed for the contract.
     */
    constructor(address _admin, address _lidoAddress, uint256 _maxTotalDeposit) {
        if(_lidoAddress == address(0)) revert ZeroAddress();
        if(_admin == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        lidoContract = ILido(_lidoAddress);
        maxTotalDeposit = _maxTotalDeposit * 1 ether;
    }

    // Admin functions

    /**
    * @notice Allows the contract's administrator to withdraw tokens to a specified address.
    * @dev Can only be called by an account with the DEFAULT_ADMIN_ROLE. It calculates the number of shares to withdraw based on the provided `_amount` of tokens and checks if the contract has enough shares to fulfill the request. If successful, it transfers the shares to the `_destination` address.
    * @param _amount The amount of staked tokens the admin wishes to withdraw.
    * @param _destination The address where the withdrawn tokens will be sent.
    * @return The result of the Lido contract's `transferShares` function call, which corresponds to the number of shares actually transferred.
    */
    function adminWithdraw(uint256 _amount, address _destination)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        returns (uint256)
    {
        if(_amount==0) revert ZeroAmount();
        // get contract shares from lidoContract
        uint256 sharesToWithdraw = lidoContract.getSharesByPooledEth(_amount);
        // validate the contract has enough shares in the lidoContract to transfer _amount
        if(sharesToWithdraw > degaTreasuryShares) revert InsufficientShares();
        degaTreasuryShares -= sharesToWithdraw;
        // call lidoContract to transfer st eth to the _destination address
        return lidoContract.transferShares(_destination, sharesToWithdraw);
    }

    /**
    * @notice This function allows accounts with the PAUSER_ROLE to pause the contract.
    * @dev Can only be executed by an account with the PAUSER_ROLE. Once the contract is paused, all functions except those marked with the `whenNotPaused` modifier become unusable until the contract is unpaused. This function is part of the OpenZeppelin Pausable contract, which provides a simple way to stop or resume execution of functions in a contract.
    * @dev No parameters are needed for this function as it doesn't require any input data to execute.
    */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
    * @notice This function allows accounts with the PAUSER_ROLE to unpause the contract.
    * @dev Can only be executed by an account with the PAUSER_ROLE. When the contract is unpaused, all functions marked with the `whenNotPaused` modifier become usable again. This function is part of the OpenZeppelin Pausable contract, which provides a simple way to stop or resume execution of functions in a contract.
    * @dev No parameters are needed for this function as it doesn't require any input data to execute.
    */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
    * @notice This function allows the contract's administrator to set the maximum total deposit limit for the contract.
    * @dev Can only be called by an account with the DEFAULT_ADMIN_ROLE. It updates the `maxTotalDeposit` variable with the new limit provided. Before updating, it checks that the new limit is greater than 0 and not less than the current total deposited. After setting the new limit, it emits a `MaxTotalDepositUpdated` event with the updated limit.
    * @param _maxTotalDeposit The new maximum total deposit limit.
    */
    function setMaxTotalDeposit(uint256 _maxTotalDeposit) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if(_maxTotalDeposit==0) revert ZeroAmount();
        if(_maxTotalDeposit < poolETHSize) revert MaxTotalCanNotBeLessThanPoolEthSize();
        maxTotalDeposit = _maxTotalDeposit;
        emit MaxTotalDepositUpdated(_maxTotalDeposit);
    }

    // User functions

    /**
    * @notice This function allows a user to deposit tokens into the contract.
    * @dev Can only be called by an external account and cannot be re-entered to prevent reentrancy attacks. It requires that the contract is not paused. The function first checks that the deposit amount is greater than 0. Then it assigns rewards to the user, calculates the shares to deposit based on the deposit amount, and ensures that the total deposited amount does not exceed the maximum total deposit limit. It also checks a tolerance condition to ensure accuracy. After these checks, it updates the user's balance and total deposited amounts, and transfers the shares from the user to the contract. Finally, it emits a `Deposit` event with the user's address, the final deposited amount, and the shares deposited.
    * @param _amount The amount of tokens the user wishes to deposit.
    * @return The final amount of tokens deposited.
    */
    function deposit(uint256 _amount) external nonReentrant returns (uint256) {
        if(_amount==0) revert ZeroAmount();
        UserInfo memory user = userInfo[msg.sender];
        // call Assign rewards function
        assignRewards();
        uint256 depositStakeShares = lidoContract.getSharesByPooledEth(_amount);
        uint256 finalDepositedAmount = lidoContract.getPooledEthByShares(depositStakeShares);
        if(poolETHSize + finalDepositedAmount > maxTotalDeposit) revert MaxTotalDepositExceeded();
        // scale deposit amount
        uint256 multiplier = accumulatedScaledBalance > 0 ? accumulatedScaledBalance : 1;
        uint256 divisor = poolETHSize > 0 ? poolETHSize : 1;
        uint256 amountToDeposit = (finalDepositedAmount * multiplier) / divisor;
        user.amount += amountToDeposit;
        user.shares += depositStakeShares;
        totalSharesDeposited += depositStakeShares;
        accumulatedScaledBalance += amountToDeposit;
        uint256 transferResult = lidoContract.transferSharesFrom(msg.sender, address(this), depositStakeShares);
        if(transferResult==0) revert DepositFailed();
        userInfo[msg.sender] = user;
        poolETHSize = lidoContract.getPooledEthByShares(totalSharesDeposited);
        emit Deposit(msg.sender, finalDepositedAmount, depositStakeShares);
        return finalDepositedAmount;
    }

    /**
    * @notice This function allows a user to withdraw tokens from the contract.
    * @dev Can only be called by an external account and cannot be re-entered to prevent reentrancy attacks. It requires that the contract is not paused. The function first assigns rewards to the user, calculates the shares to withdraw based on the withdrawal amount, and checks that the user has enough balance and shares to cover the withdrawal. After these checks, it updates the user's balance and total deposited amounts, and transfers the shares from the contract to the user. Finally, it emits a `Withdraw` event with the user's address, the withdrawal amount, and the shares withdrawn.
    * @param _amount The amount of tokens the user wishes to withdraw.
    */
    function withdraw(uint256 _amount) external nonReentrant {
        if(_amount == 0) revert ZeroAmount();
        UserInfo memory user = userInfo[msg.sender];
        assignRewards();

        // calculate the shares to withdraw
        // query lido vault to check if the user shares has enough balance to withdraw

        uint256 userMaxAmount = (user.amount * poolETHSize) / accumulatedScaledBalance;
        if(userMaxAmount == 0) revert NothingToWithdraw();
        // check max amount
        if(_amount > userMaxAmount) revert NotEnoughBalance();

        // Shares calculated according to the real amount in case of loss
        uint256 sharesToWithdraw = lidoContract.getSharesByPooledEth(_amount);
        uint256 finalWithdrawAmount = lidoContract.getPooledEthByShares(sharesToWithdraw);
        if(sharesToWithdraw > user.shares) revert InsufficientShares();
        totalSharesDeposited -= sharesToWithdraw;
        uint256 amountToDebit = (finalWithdrawAmount * accumulatedScaledBalance) / poolETHSize;
        accumulatedScaledBalance -= amountToDebit;
        user.shares -= (user.shares * amountToDebit) / user.amount;
        user.amount -= amountToDebit;
        lidoContract.transferShares(msg.sender, sharesToWithdraw);
        userInfo[msg.sender] = user;
        poolETHSize = lidoContract.getPooledEthByShares(totalSharesDeposited);
        emit Withdraw(msg.sender, finalWithdrawAmount, sharesToWithdraw);
    }

    /*
     * @notice This function allows users to withdraw their funds during an emergency situation.
     * @dev It requires that the emergency withdraw feature is enabled, and that the user has enough shares.
     * @param msg.sender The address initiating the withdrawal.
     */
    function emergencyWithdraw() external nonReentrant whenPaused {
        UserInfo memory user = userInfo[msg.sender];

        //Calculate real amount in case of loss in Lido
        if(accumulatedScaledBalance == 0) revert ZeroAmount();
        uint pooledEth = lidoContract.getPooledEthByShares(totalSharesDeposited);
        uint currentAmount = (user.amount * pooledEth) / accumulatedScaledBalance;

        if(currentAmount == 0) revert NothingToWithdraw();
        // Shares calculated according to the real user amount in case of loss
        uint256 sharesToWithdraw = lidoContract.getSharesByPooledEth(currentAmount);

        accumulatedScaledBalance -= user.amount;
        totalSharesDeposited -= sharesToWithdraw;
        user.amount = 0;
        user.shares = 0;
        userInfo[msg.sender] = user;
        uint256 withdrawnAmount = lidoContract.transferShares(msg.sender, sharesToWithdraw);
        emit EmergencyWithdraw(msg.sender, withdrawnAmount, sharesToWithdraw);
    }

    /**
     * @dev Retrieves the staked balance of a user. 
     * May not show the correct amount staked by user in case of share price decrease.
     * @param _user The user's address.
     * @return The staked balance of the user.
     */
    function getStakedBalance(address _user) external view returns (uint256) {
        if (accumulatedScaledBalance > 0) {
            return (userInfo[_user].amount * poolETHSize) / accumulatedScaledBalance;
        } else {
            return 0;
        }
    }

    // Other functions


    /**
    * @notice This function assigns rewards to users based on their stake.
    * @dev Can only be called by any account. It first checks if the total stake token deposited is not 0. If it is 0, it returns immediately. Otherwise, it calls the `rewardsCalculation` function to calculate the rewards. It then adjusts the `totalSharesDeposited` and `degaTreasuryShares` values, updates the `lastRewardAssignmentTimestamp` to the current block timestamp, and emits an `AssignRewards` event with the relevant details.
    */
    function assignRewards() public whenNotPaused {
        if (poolETHSize == 0) {
            return;
        }
        RewardCalculations memory calculationResults = rewardsCalculation();

        totalSharesDeposited -= calculationResults.sharesToAssignRewards;
        degaTreasuryShares += calculationResults.sharesToAssignRewards;
        poolETHSize = lidoContract.getPooledEthByShares(totalSharesDeposited);
        lastRewardAssignmentTimestamp = block.timestamp;
        emit AssignRewards(
            calculationResults.sharesToAssignRewards, totalSharesDeposited, block.timestamp
        );
    }

    /**
    * @notice This function calculates the rewards to be assigned to users based on their stake.
    * @dev Can only be called internally by the contract. It first converts the total shares deposited to the equivalent staked token amount. It then calculates the reward amount by subtracting the total staked token deposited from the current staked token amount. If the reward amount is less than or equal to 0, it returns a `RewardCalculations` struct with all fields set to 0. Otherwise, it converts the reward amount to the equivalent shares, constructs a `RewardCalculations` struct with the shares to assign rewards, the reward amount, and the current staked token amount, and returns this struct.
    * @return A `RewardCalculations` struct containing the shares to assign rewards to, the amount of staked tokens to be rewarded, and the current staked token amount.
    */
    function rewardsCalculation() internal view returns (RewardCalculations memory) {
        uint256 currentStAmount = lidoContract.getPooledEthByShares(totalSharesDeposited);
        // casting ints to prevent negative case overflow/underflow
        int256 currentStAmountInt = int256(currentStAmount);
        int256 poolETHSizeInt = int256(poolETHSize);
        int256 rewardStInt = currentStAmountInt - poolETHSizeInt;
        if (rewardStInt <= 0) {
            return RewardCalculations({
                sharesToAssignRewards: 0
            });
        }
        uint256 rewardSt = uint256(rewardStInt);
        uint256 sharesToAssignRewards = lidoContract.getSharesByPooledEth(rewardSt);
        RewardCalculations memory result = RewardCalculations({
            sharesToAssignRewards: sharesToAssignRewards
        });
        return result;
    }



}
