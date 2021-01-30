package api

type GitRequest struct {
	// Args for the git command to execute.
	// For example, ["add", "-u"].
	// The only allowed value currently is ["pull"].
	Args []string
}

type ListResponse []string

type ShowResponse string
