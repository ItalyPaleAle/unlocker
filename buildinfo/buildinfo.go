package buildinfo

import "fmt"

// These variables will be set at build time
var (
	AppVersion string = "canary"
	BuildId    string
	CommitHash string
	BuildDate  string
	Production string
)

// Set during initialization
var BuildDescription string

func init() {
	if BuildId != "" && BuildDate != "" && CommitHash != "" {
		BuildDescription = fmt.Sprintf("%s, %s (%s)", BuildId, BuildDate, CommitHash)
	} else {
		BuildDescription = "null"
	}
}
