package bra

type converter interface {
	Size() int
	Convert([]byte, bool) int
}

func max(x, y int) int {
	if x > y {
		return x
	}

	return y
}

func min(x, y int) int {
	if x < y {
		return x
	}

	return y
}
