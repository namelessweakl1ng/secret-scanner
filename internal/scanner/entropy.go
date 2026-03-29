package scanner

import (
	"math"
)

func CalculateEntropy(s string) float64 {
	freq := make(map[rune]int)

	for _, c := range s {
		freq[c]++
	}

	length := float64(len(s))
	var entropy float64

	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}