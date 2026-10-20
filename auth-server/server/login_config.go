package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// LoginMethodsFile is the JSON document named by MCP_AUTH_LOGIN_METHODS_FILE:
//
//	{"methods": [
//	  {"id": "google", "type": "google", "client_id_env": "...", "client_secret_env": "..."},
//	  {"id": "corp",   "type": "ldap",   "url": "ldaps://ldap.example.com", ...},
//	  {"id": "okta",   "type": "oidc",   "connector": "okta"}
//	]}
//
// Each entry has the common fields below plus the fields of its type. Unknown
// fields are an error, so a misspelled setting fails startup instead of being
// ignored.
type loginMethodsDocument struct {
	Methods []json.RawMessage `json:"methods"`
}

// loginCommon is shared by every type.
type loginCommon struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
	// SubjectPrefix overrides the "<id>:" default. An explicit empty string
	// keeps the provider's own subject, for migrating from a single connector
	// whose subjects must not change.
	SubjectPrefix *string `json:"subject_prefix"`
}

type loginOIDCEntry struct {
	loginCommon
	Connector string `json:"connector"`
}

type loginGoogleEntry struct {
	loginCommon
	ClientID        string   `json:"client_id"`
	ClientIDEnv     string   `json:"client_id_env"`
	ClientSecretEnv string   `json:"client_secret_env"`
	AllowedDomains  []string `json:"allowed_domains"`
}

type loginGitHubEntry struct {
	loginCommon
	ClientID        string   `json:"client_id"`
	ClientIDEnv     string   `json:"client_id_env"`
	ClientSecretEnv string   `json:"client_secret_env"`
	AllowedOrgs     []string `json:"allowed_orgs"`
	BaseURL         string   `json:"base_url"`
	APIURL          string   `json:"api_url"`
}

type loginLDAPEntry struct {
	loginCommon
	URL              string            `json:"url"`
	StartTLS         bool              `json:"start_tls"`
	CAFile           string            `json:"ca_file"`
	BindDN           string            `json:"bind_dn"`
	BindPasswordEnv  string            `json:"bind_password_env"`
	UserSearchBase   string            `json:"user_search_base"`
	UserFilter       string            `json:"user_filter"`
	UserDNTemplate   string            `json:"user_dn_template"`
	SubjectAttribute string            `json:"subject_attribute"`
	Claims           map[string]string `json:"claims"`
	UsernameLabel    string            `json:"username_label"`
	PasswordLabel    string            `json:"password_label"`
}

// LoginMethodsOptions carries what the loader needs from server startup.
type LoginMethodsOptions struct {
	// CallbackURL is the redirect URI each redirect method registers with its
	// provider (Config.IdentityCallbackURL).
	CallbackURL string
	// ConnectorsFile is read only when an oidc entry names a connector.
	ConnectorsFile string
	// AllowInsecure permits http endpoints and plaintext ldap://, for local
	// development.
	AllowInsecure bool
}

// LoadLoginMethods reads the file and builds the registry.
func LoadLoginMethods(path string, options LoginMethodsOptions) (*LoginRegistry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read login methods file: %w", err)
	}
	return ParseLoginMethods(data, options)
}

// ParseLoginMethods builds the registry from the file's contents.
func ParseLoginMethods(data []byte, options LoginMethodsOptions) (*LoginRegistry, error) {
	var document loginMethodsDocument
	if err := strictJSON(data, &document); err != nil {
		return nil, fmt.Errorf("parse login methods: %w", err)
	}
	var entries []LoginEntry
	var connectors map[string]ConnectorConfig
	for index, raw := range document.Methods {
		var common loginCommon
		if err := json.Unmarshal(raw, &common); err != nil {
			return nil, fmt.Errorf("login method %d: %w", index+1, err)
		}
		if common.ID == "" {
			return nil, fmt.Errorf("login method %d: id is required", index+1)
		}
		label := common.Label
		method, err := func() (LoginMethod, error) {
			switch common.Type {
			case "oidc":
				var entry loginOIDCEntry
				if err := strictJSON(raw, &entry); err != nil {
					return nil, err
				}
				if entry.Connector == "" {
					return nil, errors.New("connector is required")
				}
				if connectors == nil {
					if options.ConnectorsFile == "" {
						return nil, errors.New("oidc methods need MCP_AUTH_CONNECTORS_FILE")
					}
					loaded, err := LoadConnectorsWithOptions(options.ConnectorsFile, options.AllowInsecure)
					if err != nil {
						return nil, err
					}
					connectors = loaded
				}
				connector, ok := connectors[entry.Connector]
				if !ok {
					return nil, fmt.Errorf("connector %q is not in the connectors file", entry.Connector)
				}
				provider, err := NewOIDCIdentityProvider(connector, options.CallbackURL, options.AllowInsecure)
				if err != nil {
					return nil, err
				}
				return NewOIDCLoginMethod(common.ID, defaultLabel(label, "Sign in with "+entry.Connector), provider, nil), nil
			case "google":
				var entry loginGoogleEntry
				if err := strictJSON(raw, &entry); err != nil {
					return nil, err
				}
				return NewGoogleLoginMethod(GoogleConfig{
					ID: common.ID, Label: defaultLabel(label, "Sign in with Google"),
					ClientID: entry.ClientID, ClientIDEnv: entry.ClientIDEnv, ClientSecretEnv: entry.ClientSecretEnv,
					AllowedDomains: entry.AllowedDomains,
				}, options.CallbackURL, options.AllowInsecure)
			case "github":
				var entry loginGitHubEntry
				if err := strictJSON(raw, &entry); err != nil {
					return nil, err
				}
				return NewGitHubLoginMethod(GitHubConfig{
					ID: common.ID, Label: defaultLabel(label, "Sign in with GitHub"),
					ClientID: entry.ClientID, ClientIDEnv: entry.ClientIDEnv, ClientSecretEnv: entry.ClientSecretEnv,
					AllowedOrgs: entry.AllowedOrgs, BaseURL: entry.BaseURL, APIURL: entry.APIURL,
				}, options.CallbackURL, options.AllowInsecure)
			case "ldap":
				var entry loginLDAPEntry
				if err := strictJSON(raw, &entry); err != nil {
					return nil, err
				}
				return NewLDAPLoginMethod(LDAPConfig{
					ID: common.ID, Label: defaultLabel(label, "Sign in with your directory account"),
					URL: entry.URL, StartTLS: entry.StartTLS, CAFile: entry.CAFile,
					BindDN: entry.BindDN, BindPasswordEnv: entry.BindPasswordEnv,
					UserSearchBase: entry.UserSearchBase, UserFilter: entry.UserFilter,
					UserDNTemplate: entry.UserDNTemplate, SubjectAttribute: entry.SubjectAttribute,
					Claims: entry.Claims, UsernameLabel: entry.UsernameLabel, PasswordLabel: entry.PasswordLabel,
				}, options.AllowInsecure)
			case "":
				return nil, errors.New("type is required (oidc, google, github or ldap)")
			default:
				return nil, fmt.Errorf("unknown type %q (supported: oidc, google, github, ldap)", common.Type)
			}
		}()
		if err != nil {
			return nil, fmt.Errorf("login method %q: %w", common.ID, err)
		}
		prefix := common.ID + ":"
		if common.SubjectPrefix != nil {
			prefix = *common.SubjectPrefix
		}
		entries = append(entries, LoginEntry{Method: method, SubjectPrefix: prefix})
	}
	return NewLoginRegistry(entries...)
}

func defaultLabel(label, fallback string) string {
	if label != "" {
		return label
	}
	return fallback
}

// strictJSON decodes data into target and rejects unknown fields and trailing
// content.
func strictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("unexpected content after the JSON document")
	}
	return nil
}
