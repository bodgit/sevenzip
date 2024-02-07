package bra

type converter interface {
	Size() int
	Convert([]byte, bool) int
}
