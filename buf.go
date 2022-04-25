package anonymization

const (
	lowerBound       = 32
	allocationFactor = 4
)

// AnonymizeBuf allocates a buffer which can be used for anonymizing sip header fields
func AnonymizeBuf(l int) []byte {
	if l < lowerBound {
		l = lowerBound
	}
	return make([]byte, allocationFactor*l)
}
