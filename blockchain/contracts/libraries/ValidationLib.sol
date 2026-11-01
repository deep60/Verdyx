// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ValidationLib
 * @dev Library for common validation operations in the Verdyx platform
 * @notice Provides reusable validation functions with custom error messages
 */
library ValidationLib {
    // ============ CUSTOM ERRORS ============

    error InvalidAddress();
    error InvalidAmount();
    error InvalidTimestamp();
    error InvalidString();
    error InvalidPercentage();
    error InvalidRange();
    error DeadlinePassed();
    error DeadlineTooSoon();
    error AmountTooLow(uint256 provided, uint256 minimum);
    error AmountTooHigh(uint256 provided, uint256 maximum);
    error ArrayLengthMismatch(uint256 length1, uint256 length2);
    error EmptyArray();
    error InvalidIPFSHash();
    error InvalidConfidence();

    // ============ ADDRESS VALIDATION ============

    /**
     * @dev Validate that an address is not zero
     * @param addr Address to validate
     */
    function requireValidAddress(address addr) internal pure {
        if (addr == address(0)) revert InvalidAddress();
    }

    /**
     * @dev Validate multiple addresses
     * @param addresses Array of addresses to validate
     */
    function requireValidAddresses(address[] memory addresses) internal pure {
        for (uint256 i = 0; i < addresses.length; i++) {
            requireValidAddress(addresses[i]);
        }
    }

    /**
     * @dev Check if address is valid without reverting
     * @param addr Address to check
     * @return bool True if valid, false otherwise
     */
    function isValidAddress(address addr) internal pure returns (bool) {
        return addr != address(0);
    }

    // ============ AMOUNT VALIDATION ============

    /**
     * @dev Validate that an amount is greater than zero
     * @param amount Amount to validate
     */
    function requireNonZeroAmount(uint256 amount) internal pure {
        if (amount == 0) revert InvalidAmount();
    }

    /**
     * @dev Validate that an amount is within a range
     * @param amount Amount to validate
     * @param min Minimum allowed value
     * @param max Maximum allowed value
     */
    function requireAmountInRange(
        uint256 amount,
        uint256 min,
        uint256 max
    ) internal pure {
        if (amount < min) revert AmountTooLow(amount, min);
        if (amount > max) revert AmountTooHigh(amount, max);
    }

    /**
     * @dev Validate minimum amount
     * @param amount Amount to validate
     * @param minimum Minimum required amount
     */
    function requireMinimumAmount(
        uint256 amount,
        uint256 minimum
    ) internal pure {
        if (amount < minimum) revert AmountTooLow(amount, minimum);
    }

    /**
     * @dev Validate maximum amount
     * @param amount Amount to validate
     * @param maximum Maximum allowed amount
     */
    function requireMaximumAmount(
        uint256 amount,
        uint256 maximum
    ) internal pure {
        if (amount > maximum) revert AmountTooHigh(amount, maximum);
    }

    // ============ TIMESTAMP VALIDATION ============

    /**
     * @dev Validate that a deadline is in the future
     * @param deadline Timestamp to validate
     * @param minimumDelay Minimum delay from now (in seconds)
     */
    function requireFutureDeadline(
        uint256 deadline,
        uint256 minimumDelay
    ) internal view {
        if (deadline <= block.timestamp) revert DeadlinePassed();
        if (deadline < block.timestamp + minimumDelay) revert DeadlineTooSoon();
    }

    /**
     * @dev Validate that current time is before deadline
     * @param deadline Timestamp to check against
     */
    function requireBeforeDeadline(uint256 deadline) internal view {
        if (block.timestamp > deadline) revert DeadlinePassed();
    }

    /**
     * @dev Check if deadline has passed
     * @param deadline Timestamp to check
     * @return bool True if deadline has passed
     */
    function isDeadlinePassed(uint256 deadline) internal view returns (bool) {
        return block.timestamp > deadline;
    }

    // ============ STRING VALIDATION ============

    /**
     * @dev Validate that a string is not empty
     * @param str String to validate
     */
    function requireNonEmptyString(string memory str) internal pure {
        if (bytes(str).length == 0) revert InvalidString();
    }

    /**
     * @dev Validate string length
     * @param str String to validate
     * @param minLength Minimum length
     * @param maxLength Maximum length
     */
    function requireStringLength(
        string memory str,
        uint256 minLength,
        uint256 maxLength
    ) internal pure {
        uint256 length = bytes(str).length;
        if (length < minLength || length > maxLength) revert InvalidRange();
    }

    /**
     * @dev Validate IPFS hash format (simple check for length)
     * @param hash IPFS hash to validate
     */
    function requireValidIPFSHash(string memory hash) internal pure {
        uint256 length = bytes(hash).length;
        // IPFS CIDv0 is 46 characters, CIDv1 can vary but typically 59+
        if (length < 46 || length > 100) revert InvalidIPFSHash();
    }

    // ============ ARRAY VALIDATION ============

    /**
     * @dev Validate that two arrays have the same length
     * @param array1Length Length of first array
     * @param array2Length Length of second array
     */
    function requireSameLength(
        uint256 array1Length,
        uint256 array2Length
    ) internal pure {
        if (array1Length != array2Length) {
            revert ArrayLengthMismatch(array1Length, array2Length);
        }
    }

    /**
     * @dev Validate that array is not empty
     * @param length Array length
     */
    function requireNonEmptyArray(uint256 length) internal pure {
        if (length == 0) revert EmptyArray();
    }

    // ============ PERCENTAGE VALIDATION ============

    /**
     * @dev Validate percentage (0-100)
     * @param percentage Percentage to validate
     */
    function requireValidPercentage(uint256 percentage) internal pure {
        if (percentage > 100) revert InvalidPercentage();
    }

    /**
     * @dev Validate basis points (0-10000, where 10000 = 100%)
     * @param basisPoints Basis points to validate
     */
    function requireValidBasisPoints(uint256 basisPoints) internal pure {
        if (basisPoints > 10000) revert InvalidPercentage();
    }

    /**
     * @dev Validate confidence score (0-100)
     * @param confidence Confidence score to validate
     */
    function requireValidConfidence(uint256 confidence) internal pure {
        if (confidence == 0 || confidence > 100) revert InvalidConfidence();
    }

    // ============ COMPARISON UTILITIES ============

    /**
     * @dev Check if value is within range (inclusive)
     * @param value Value to check
     * @param min Minimum value
     * @param max Maximum value
     * @return bool True if within range
     */
    function isWithinRange(
        uint256 value,
        uint256 min,
        uint256 max
    ) internal pure returns (bool) {
        return value >= min && value <= max;
    }

    /**
     * @dev Safe comparison for values with tolerance
     * @param value1 First value
     * @param value2 Second value
     * @param tolerance Acceptable difference
     * @return bool True if values are within tolerance
     */
    function isWithinTolerance(
        uint256 value1,
        uint256 value2,
        uint256 tolerance
    ) internal pure returns (bool) {
        if (value1 > value2) {
            return (value1 - value2) <= tolerance;
        } else {
            return (value2 - value1) <= tolerance;
        }
    }
}
