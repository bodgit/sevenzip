package bra

type converter interface {
	Size() int
	Convert(b []byte, encoding bool) int
}
