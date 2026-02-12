package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", handleRequest)

	log.Printf("Test app listening on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
    <title>OIDC Test App</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-top: 0; }
        h2 { color: #666; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-top: 30px; }
        .header-row { display: flex; padding: 8px 0; border-bottom: 1px solid #f0f0f0; }
        .header-name { font-weight: bold; width: 250px; color: #555; }
        .header-value { flex: 1; word-break: break-all; color: #333; }
        .highlight { background: #e8f5e9; padding: 15px; border-radius: 4px; border-left: 4px solid #4caf50; }
        .token-section { background: #f5f5f5; padding: 15px; border-radius: 4px; margin-top: 10px; }
        .token-claims { background: #fff3e0; padding: 15px; border-radius: 4px; margin-top: 10px; border-left: 4px solid #ff9800; }
        pre { margin: 0; white-space: pre-wrap; word-break: break-all; font-size: 13px; }
        .success { color: #4caf50; }
        .warning { color: #ff9800; }
        a { color: #1976d2; }
    </style>
</head>
<body>
    <div class="container">
        <h1>OIDC PKCE Test Application</h1>
        <p>This app displays incoming request headers to verify OIDC authentication is working.</p>
`)

	// Check for Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		fmt.Fprint(w, `
        <h2 class="success">Authentication Successful</h2>
        <div class="highlight">
            <strong>Bearer Token Received</strong>
        </div>
        <div class="token-section">
            <strong>Access Token:</strong>
            <pre>`+html.EscapeString(token)+`</pre>
        </div>
`)

		// Try to decode JWT payload
		claims := decodeJWTPayload(token)
		if claims != nil {
			claimsJSON, _ := json.MarshalIndent(claims, "", "  ")
			fmt.Fprint(w, `
        <div class="token-claims">
            <strong>Decoded Token Claims:</strong>
            <pre>`+html.EscapeString(string(claimsJSON))+`</pre>
        </div>
`)
		}
	} else {
		fmt.Fprint(w, `
        <h2 class="warning">No Authentication Token</h2>
        <p>No Bearer token found in Authorization header. The OIDC middleware may not be configured correctly.</p>
`)
	}

	// Display all headers
	fmt.Fprint(w, `
        <h2>Request Headers</h2>
        <div>
`)

	// Sort headers for consistent display
	var headerNames []string
	for name := range r.Header {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)

	for _, name := range headerNames {
		values := r.Header[name]
		for _, value := range values {
			displayValue := value
			// Truncate very long values
			if len(displayValue) > 500 {
				displayValue = displayValue[:500] + "..."
			}
			rowClass := ""
			if name == "Authorization" {
				rowClass = ` style="background: #e8f5e9;"`
			}
			fmt.Fprintf(w, `            <div class="header-row"%s>
                <div class="header-name">%s</div>
                <div class="header-value">%s</div>
            </div>
`, rowClass, html.EscapeString(name), html.EscapeString(displayValue))
		}
	}

	fmt.Fprint(w, `
        </div>

        <h2>Request Info</h2>
        <div>
            <div class="header-row">
                <div class="header-name">Method</div>
                <div class="header-value">`+html.EscapeString(r.Method)+`</div>
            </div>
            <div class="header-row">
                <div class="header-name">URL</div>
                <div class="header-value">`+html.EscapeString(r.URL.String())+`</div>
            </div>
            <div class="header-row">
                <div class="header-name">Host</div>
                <div class="header-value">`+html.EscapeString(r.Host)+`</div>
            </div>
            <div class="header-row">
                <div class="header-name">Remote Address</div>
                <div class="header-value">`+html.EscapeString(r.RemoteAddr)+`</div>
            </div>
        </div>

        <p style="margin-top: 30px; color: #666;">
            <a href="/oauth2/logout">Logout</a>
        </p>
    </div>
</body>
</html>
`)
}

func decodeJWTPayload(token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try with padding
		payload, err = base64.StdEncoding.DecodeString(addPadding(parts[1]))
		if err != nil {
			return nil
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}

	return claims
}

func addPadding(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}
