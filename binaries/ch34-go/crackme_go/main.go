// crackme_go — Training binary for Chapter 34
// Reverse Engineering Training — Applications compiled with the GNU toolchain
//
// Pedagogical objective:
//   This crackme illustrates Go internal structures visible in RE:
//   - Interfaces and dynamic dispatch (section 34.3)
//   - Goroutines and channels (section 34.1)
//   - Slices, maps and Go strings (sections 34.3 / 34.5)
//   - Go calling convention (section 34.2)
//   - Function names in gopclntab (section 34.4)
//
// Usage : ./crackme_go <LICENSE_KEY>
// Expected format: XXXX-XXXX-XXXX-XXXX (hex uppercase)
//
// MIT License — Strictly educational use.

package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// Constants and reference table
// ---------------------------------------------------------------------------

// magic is used as an XOR seed for validation.
// In RE, this constant is identifiable via strings or .rodata.
var magic = [4]byte{0xDE, 0xAD, 0xC0, 0xDE}

// expectedSums is the expected checksum table for each group.
// Each group is 2 bytes; after XOR with magic[0] and magic[1],
// the sum must match the value below.
// The analyst must extract these values to write a keygen.
var expectedSums = map[int]uint16{
	0: 0x010E, // 270
	1: 0x0122, // 290
	2: 0x0136, // 310
	3: 0x013E, // 318
}

// ---------------------------------------------------------------------------
// Interface Validator — illustrates Go virtual dispatch (itab)
// ---------------------------------------------------------------------------

// Validator is an interface with a single method.
// In assembly, the call will go through an itab (interface table).
type Validator interface {
	Validate(group []byte, index int) bool
}

// ---------------------------------------------------------------------------
// ChecksumValidator — verifies the XORed byte sum of a group
// ---------------------------------------------------------------------------

// ChecksumValidator implements Validator.
type ChecksumValidator struct {
	ExpectedSums map[int]uint16
}

// Validate sums the group bytes XORed with magic,
// then compares with the expected sum.
func (cv *ChecksumValidator) Validate(group []byte, index int) bool {
	var sum uint16
	for i, b := range group {
		xored := b ^ magic[i%len(magic)]
		sum += uint16(xored)
	}
	expected, ok := cv.ExpectedSums[index]
	if !ok {
		return false
	}
	return sum == expected
}

// ---------------------------------------------------------------------------
// Key parsing
// ---------------------------------------------------------------------------

// parseKey verifies the format XXXX-XXXX-XXXX-XXXX and returns 4 groups
// of 2 bytes each (each "XXXX" = 2 hex bytes).
func parseKey(key string) ([][2]byte, error) {
	parts := strings.Split(key, "-")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid format: expected 4 groups separated by '-'")
	}

	groups := make([][2]byte, 4)
	for i, part := range parts {
		if len(part) != 4 {
			return nil, fmt.Errorf("group %d: expected 4 hex characters, got %d", i+1, len(part))
		}
		for j := 0; j < 2; j++ {
			hi := hexVal(part[j*2])
			lo := hexVal(part[j*2+1])
			if hi < 0 || lo < 0 {
				return nil, fmt.Errorf("group %d: non-hex character detected", i+1)
			}
			groups[i][j] = byte(hi<<4) | byte(lo)
		}
	}
	return groups, nil
}

// hexVal converts an ASCII hex character to value 0-15.
// Returns -1 if the character is not valid hexadecimal.
func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return -1
	}
}

// ---------------------------------------------------------------------------
// Concurrent validation — illustrates goroutines + channels + WaitGroup
// ---------------------------------------------------------------------------

// validationResult carries the result of a validation goroutine.
type validationResult struct {
	Index int
	OK    bool
}

// validateGroups launches one goroutine per group for checksum validation.
// Uses a channel to collect results and a WaitGroup to
// synchronization — classic patterns visible in Go RE.
func validateGroups(groups [][2]byte, v Validator) bool {
	ch := make(chan validationResult, len(groups))
	var wg sync.WaitGroup

	for i, g := range groups {
		wg.Add(1)
		go func(idx int, data [2]byte) {
			defer wg.Done()
			ok := v.Validate(data[:], idx)
			ch <- validationResult{Index: idx, OK: ok}
		}(i, g)
	}

	// Close the channel once all goroutines are done.
	go func() {
		wg.Wait()
		close(ch)
	}()

	for res := range ch {
		if !res.OK {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Cross validation — relationship between all groups
// ---------------------------------------------------------------------------

// validateCross verifies that the global XOR of all key bytes
// produces the expected value (0x42). This is a global integrity check.
func validateCross(groups [][2]byte) bool {
	var globalXOR byte
	for _, g := range groups {
		for _, b := range g {
			globalXOR ^= b
		}
	}
	return globalXOR == 0x42
}

// ---------------------------------------------------------------------------
// Group order verification
// ---------------------------------------------------------------------------

// validateOrder ensures that the first byte of each group
// is strictly increasing. This constraint imposes an order
// on groups and reduces the valid key space.
func validateOrder(groups [][2]byte) bool {
	prev := -1
	for _, g := range groups {
		val := int(g[0])
		if val <= prev {
			return false
		}
		prev = val
	}
	return true
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	banner := `
   ╔══════════════════════════════════════════╗
   ║   crackme_go — Chapter 34              ║
   ║   Reverse Engineering GNU Training      ║
   ╚══════════════════════════════════════════╝`
	fmt.Println(banner)

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "\nUsage : %s <LICENSE_KEY>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Format : XXXX-XXXX-XXXX-XXXX (hex uppercase)\n\n")
		os.Exit(1)
	}

	key := os.Args[1]
	groups, err := parseKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[ERROR] %s\n\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n[*] Key verification: %s\n", key)

	// Step 1 — Per-group checksum validation (via interface + goroutines)
	cv := &ChecksumValidator{ExpectedSums: expectedSums}
	if !validateGroups(groups, cv) {
		fmt.Println("[✗] Failure: invalid group checksum.")
		os.Exit(1)
	}
	fmt.Println("[✓] Group checksums valid.")

	// Step 2 — Ascending order validation
	if !validateOrder(groups) {
		fmt.Println("[✗] Failure: order constraint not met.")
		os.Exit(1)
	}
	fmt.Println("[✓] Order constraint met.")

	// Step 3 — Global XOR cross validation
	if !validateCross(groups) {
		fmt.Println("[✗] Failure: cross verification failed.")
		os.Exit(1)
	}
	fmt.Println("[✓] Cross verification OK.")

	// Success
	fmt.Println("\n══════════════════════════════════════")
	fmt.Println("  🎉  Valid key! Well done, reverser!  ")
	fmt.Println("══════════════════════════════════════\n")
}
