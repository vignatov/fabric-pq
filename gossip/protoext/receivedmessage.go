/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protoext

import (
	"context"
	"fmt"

	"github.com/hyperledger/fabric-protos-go-apiv2/gossip"
	"github.com/hyperledger/fabric/gossip/api"
	"github.com/hyperledger/fabric/gossip/common"
)

// ChannelAdmission obtains the serving generation of a protected channel.
// A nil admission function gives a baseline channel an unguarded scope.
type ChannelAdmission func() (context.Context, func(), bool)

func (a ChannelAdmission) Acquire() (context.Context, func(), bool) {
	if a == nil {
		return nil, func() {}, true
	}
	return a()
}

// AckInGeneration returns an acknowledgement within the same reply scope.
func AckInGeneration(msg ReceivedMessage, err error, generation context.Context) {
	if generation == nil {
		msg.Ack(err)
		return
	}
	ack := &gossip.Acknowledgement{}
	if err != nil {
		ack.Error = err.Error()
	}
	RespondInGeneration(msg, &gossip.GossipMessage{
		Nonce:   msg.GetGossipMessage().GetNonce(),
		Content: &gossip.GossipMessage_Ack{Ack: ack},
	}, generation)
}

// RespondInGeneration sends a response before the caller releases admission.
// A protected reply requires a transport that can abort a blocked send.
func RespondInGeneration(msg ReceivedMessage, response *gossip.GossipMessage, generation context.Context) {
	if generation == nil {
		msg.Respond(response)
		return
	}
	if sender, ok := msg.(interface {
		RespondWithGeneration(*gossip.GossipMessage, context.Context)
	}); ok {
		sender.RespondWithGeneration(response, generation)
	}
}

// ReceivedMessage is a GossipMessage wrapper that
// enables the user to send a message to the origin from which
// the ReceivedMessage was sent from.
// It also allows to know the identity of the sender,
// to obtain the raw bytes the GossipMessage was un-marshaled from,
// and the signature over these raw bytes.
//
// A ReceivedMessage obtained from a gossip communication layer holds
// receive-path resources accounted against the sender's connection and the
// node-wide budget; once done with the message, the consumer must release
// them by calling comm.DisposeMessage (or the message's Dispose method, when
// the concrete implementation exposes one).
type ReceivedMessage interface {
	// Respond sends a GossipMessage to the origin from which this ReceivedMessage was sent from
	Respond(msg *gossip.GossipMessage)

	// GetGossipMessage returns the underlying GossipMessage
	GetGossipMessage() *SignedGossipMessage

	// GetSourceEnvelope Returns the Envelope the ReceivedMessage was
	// constructed with
	GetSourceEnvelope() *gossip.Envelope

	// GetConnectionInfo returns information about the remote peer
	// that sent the message
	GetConnectionInfo() *ConnectionInfo

	// Ack returns to the sender an acknowledgement for the message
	// An ack can receive an error that indicates that the operation related
	// to the message has failed
	Ack(err error)
}

// ConnectionInfo represents information about
// the remote peer that sent a certain ReceivedMessage
type ConnectionInfo struct {
	ID       common.PKIidType
	Auth     *AuthInfo
	Identity api.PeerIdentityType
	Endpoint string
}

// String returns a string representation of this ConnectionInfo
func (c *ConnectionInfo) String() string {
	return fmt.Sprintf("%s %v", c.Endpoint, c.ID)
}

// AuthInfo represents the authentication
// data that was provided by the remote peer
// at the connection time
type AuthInfo struct {
	SignedData []byte
	Signature  []byte
}
