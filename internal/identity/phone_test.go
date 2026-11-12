package identity

import "testing"

func TestPhoneNormalization(t *testing.T) {
	for _, number := range []string{"19900000001", "+8619900000001"} {
		normalized, err := NormalizePhone(number)
		if err != nil || normalized != "+8619900000001" {
			t.Fatal("unexpected phone normalization")
		}
	}
	for _, number := range []string{"", "+1 202 555 0100", " 19900000001", "19900000001 ", "12900000001", "1990000000x", "+861990000000"} {
		if _, err := NormalizePhone(number); err == nil {
			t.Fatal("accepted unsupported phone format")
		}
	}
}
