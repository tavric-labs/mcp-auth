module github.com/Agent-Hellboy/mcp-auth/combined-server

go 1.26.0

require (
	github.com/Agent-Hellboy/mcp-auth/auth-server v0.0.0
	github.com/Agent-Hellboy/mcp-auth/credential-gateway v0.0.0
)

require (
	github.com/Agent-Hellboy/mcp-auth/auth-client/go v0.4.0 // indirect
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-ldap/ldap/v3 v3.4.15 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	modernc.org/libc v1.55.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/sqlite v1.34.5 // indirect
)

replace github.com/Agent-Hellboy/mcp-auth/auth-server => ../auth-server

replace github.com/Agent-Hellboy/mcp-auth/auth-client/go => ../auth-client/go

replace github.com/Agent-Hellboy/mcp-auth/credential-gateway => ../credential-gateway
