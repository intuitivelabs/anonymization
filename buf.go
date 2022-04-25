package anonymization

const (
	lowerBound       = 32
	allocationFactor = 4
)

// AnonymizeBuf allocates a buffer which can be used for anonymizing arbitrary plain text.
// 'l' is representing the length of the plain text to be anonymized.
func AnonymizeBuf(l int) []byte {
	if l < lowerBound {
		l = lowerBound
	}
	return make([]byte, allocationFactor*l)
}
