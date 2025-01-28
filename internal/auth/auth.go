package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != "ApiKey" {
		return "", errors.New("malformed authorization header")
	}

	return splitAuth[1], nil
}

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}{
		{
			name:    "No Authorization header",
			headers: http.Header{},
			want:    "Asdfdsafdsf",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization header",
			headers: http.Header{
				"Authorization": []string{"Bearer token"},
			},
			want:    "sdfsf",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "Correct Authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey correct_api_key"},
			},
			want:    "correct_api_key",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if got != tt.want || (err != nil && err.Error() != tt.wantErr.Error()) {
				t.Errorf("GetAPIKey() = %v, %v; want %v, %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}
