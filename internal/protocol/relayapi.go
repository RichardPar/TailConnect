package protocol

import "tailconnect/internal/key"

// The relay API lets a standalone relay (tc-relay) ask the control server
// which machines it may serve. Requests carry the relay's token in
// "Authorization: Bearer tc-relay-...". Paths are under RelayAPIPath.
const RelayAPIPath = "/relay-api/v1/"

// RelayAuthorizeRequest (POST authorize): may this machine connect?
type RelayAuthorizeRequest struct {
	Node key.NodePublic
}

// RelayAuthorizeResponse: Reason says why not, when Allowed is false.
type RelayAuthorizeResponse struct {
	Allowed    bool
	Reason     string `json:",omitempty"`
	Generation int64
}

// RelayAllowedRequest (POST allowed): may the relay carry packets between
// each pair (in either direction)?
type RelayAllowedRequest struct {
	Pairs [][2]key.NodePublic
}

// RelayAllowedResponse answers each pair, as of Generation.
type RelayAllowedResponse struct {
	Allowed    []bool
	Generation int64
}

// RelayWatchResponse (GET watch?generation=G) is returned once the
// generation differs from G, or after a while regardless: answers given
// for an older generation may be out of date.
type RelayWatchResponse struct {
	Generation int64
}
