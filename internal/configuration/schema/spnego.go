package schema

type SPNEGO struct {
	Disable bool   `koanf:"disable" json:"disable" jsonschema:"default=false,title=Disable" jsonschema_description:"Disables the WebAuthn 2FA functionality."`
	Keytab  string `koanf:"keytab" json:"keytab" jsonschema:"title=File Path" jsonschema_description:"The filepath to the kerberos keytab."`
}
