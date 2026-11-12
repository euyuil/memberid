package identity

import (
	"context"
	"errors"
	"testing"
)

func TestInvalidDatabaseSettings(t *testing.T) {
	for _, configuration := range []string{"", " ", "postgres://example:invalid%zz@localhost/database"} {
		if err := Initialize(context.Background(), configuration); !errors.Is(err, ErrDatabaseConfiguration) {
			t.Fatalf("initialization did not reject malformed settings: %v", err)
		}
		store, err := Open(context.Background(), configuration)
		if store != nil || !errors.Is(err, ErrDatabaseConfiguration) {
			t.Fatalf("opening did not reject malformed settings: %v", err)
		}
	}
}
