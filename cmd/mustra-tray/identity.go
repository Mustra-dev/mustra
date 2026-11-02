package main

// Identity shared by the toast, the registry entries and the URI a toast
// button carries. Not in the Windows-only files: the client code builds
// those URIs, and it has to compile everywhere the repository does.
//
// appUserModelID is what makes a toast ours. Without an AUMID that Windows
// recognises, a notification shows under whatever process raised it -- which
// would be "Windows PowerShell", with PowerShell's icon, on an endpoint
// being told its machine is about to restart.
const (
	appUserModelID = "mustra-dev.mustra.agent"
	protocolScheme = "mustra"
	displayName    = "mustra"
)
