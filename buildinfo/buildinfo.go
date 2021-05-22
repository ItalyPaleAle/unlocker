package buildinfo

// These variables will be set at build time
var (
	AppVersion string = "canary"
	BuildId    string
	CommitHash string
	BuildDate  string
	Production string
)
