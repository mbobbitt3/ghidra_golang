package main

import (
	"fmt"
	"strings"
)

// Function to reverse a string
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < len(runes)/2; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// Function to count the number of vowels in a string
func countVowels(s string) int {
	count := 0
	vowels := "aeiouAEIOU"
	for _, char := range s {
		if strings.ContainsRune(vowels, char) {
			count++
		}
	}
	return count
}

// Function to check if a string is a palindrome
func isPalindrome(s string) bool {
	reversed := reverseString(s)
	return strings.EqualFold(s, reversed)
}

func main() {
	// Sample strings
	str1 := "hello"
	str2 := "racecar"
	str3 := "Go programming"
	str4 := "GoOoG"

	// Reverse strings
	fmt.Println("Reversed strings:")
	fmt.Println(reverseString(str1))
	fmt.Println(reverseString(str2))
	fmt.Println(reverseString(str3))
	fmt.Println(reverseString(str4))

	// Count vowels
	fmt.Println("\nNumber of vowels:")
	fmt.Println("In", str1+":", countVowels(str1))
	fmt.Println("In", str2+":", countVowels(str2))
	fmt.Println("In", str3+":", countVowels(str3))
	fmt.Println("In", str4+":", countVowels(str4))

	// Check for palindrome
	fmt.Println("\nPalindromes:")
	fmt.Println(str1, "is palindrome:", isPalindrome(str1))
	fmt.Println(str2, "is palindrome:", isPalindrome(str2))
	fmt.Println(str3, "is palindrome:", isPalindrome(str3))
	fmt.Println(str4, "is palindrome:", isPalindrome(str4))
}
