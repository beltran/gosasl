package gosasl

import (
	"encoding/binary"
	"fmt"
	"github.com/beltran/gssapi"
	"log"
	"regexp"
)

const DEFAULT_MAX_LENGTH = 16384000

var (
	krbSPNHost = regexp.MustCompile(`\A[^/]+/(_HOST)([@/]|\z)`)
)

var AUTH = "auth"
var AUTH_INT = "auth-int"
var AUTH_CONF = "auth-conf"

var QOP_TO_FLAG = map[string]byte{
	AUTH:      1,
	AUTH_INT:  2,
	AUTH_CONF: 4,
}

type QOP []byte

// MechanismConfig is the configuration to use for mechanisms
type MechanismConfig struct {
	name               string
	score              int
	complete           bool
	hasInitialResponse bool
	allowsAnonymous    bool
	usesPlaintext      bool
	activeSafe         bool
	dictionarySafe     bool
	qop                QOP
	authorizationID    string
}

// Mechanism is the common interface for all mechanisms
type Mechanism interface {
	step(challenge []byte) ([]byte, error)
	wrap(outgoing []byte) ([]byte, error)
	unwrap(incoming []byte) ([]byte, error)
	dispose()
	getConfig() *MechanismConfig
}

// AnonymousMechanism corresponds to NONE/ Anonymous SASL mechanism
type AnonymousMechanism struct {
	mechanismConfig *MechanismConfig
}

// NewAnonymousMechanism returns a new AnonymousMechanism
func NewAnonymousMechanism() *AnonymousMechanism {
	return &AnonymousMechanism{
		mechanismConfig: newDefaultConfig("Anonymous"),
	}
}

func (m *AnonymousMechanism) step([]byte) ([]byte, error) {
	return []byte("Anonymous, None"), nil
}

func (m *AnonymousMechanism) wrap([]byte) ([]byte, error) {
	return nil, nil
}

func (m *AnonymousMechanism) unwrap([]byte) ([]byte, error) {
	return nil, nil
}

func (m *AnonymousMechanism) dispose() {}

func (m *AnonymousMechanism) getConfig() *MechanismConfig {
	return m.mechanismConfig
}

// PlainMechanism corresponds to PLAIN SASL mechanism
type PlainMechanism struct {
	mechanismConfig *MechanismConfig
	identity        string
	username        string
	password        string
}

// NewPlainMechanism returns a new PlainMechanism
func NewPlainMechanism(username string, password string) *PlainMechanism {
	return &PlainMechanism{
		mechanismConfig: newDefaultConfig("PLAIN"),
		username:        username,
		password:        password,
	}
}

func (m *PlainMechanism) step(challenge []byte) ([]byte, error) {
	m.mechanismConfig.complete = true
	var authID string

	if m.mechanismConfig.authorizationID != "" {
		authID = m.mechanismConfig.authorizationID
	} else {
		authID = m.identity
	}
	NULL := "\x00"
	return []byte(fmt.Sprintf("%s%s%s%s%s", authID, NULL, m.username, NULL, m.password)), nil
}

func (m *PlainMechanism) wrap(outgoing []byte) ([]byte, error) {
	return outgoing, nil
}

func (m *PlainMechanism) unwrap(incoming []byte) ([]byte, error) {
	return incoming, nil
}

func (m *PlainMechanism) dispose() {
	m.password = ""
}

func (m *PlainMechanism) getConfig() *MechanismConfig {
	return m.mechanismConfig
}

// GSSAPIMechanism corresponds to GSSAPI SASL mechanism
type GSSAPIMechanism struct {
	mechanismConfig  *MechanismConfig
	user             string
	host             string
	service          string
	principal        string
	negotiationStage int
	context          *GSSAPIContext
	qop              byte
	supportedQop     uint8
	userSelectQop    uint8
	serverMaxLength  int
	maxLength        int
}

// NewGSSAPIMechanism returns a new GSSAPIMechanism
func NewGSSAPIMechanism(host string, service string, principal string) (mechanism *GSSAPIMechanism, err error) {
	context := NewGSSAPIContext()
	mechanism = &GSSAPIMechanism{
		mechanismConfig:  newDefaultConfig("GSSAPI"),
		user:             "",
		host:             host,
		service:          service,
		principal:        principal,
		negotiationStage: 0,
		context:          context,
		maxLength:        DEFAULT_MAX_LENGTH,
		supportedQop:     QOP_TO_FLAG[AUTH] | QOP_TO_FLAG[AUTH_CONF] | QOP_TO_FLAG[AUTH_INT],
		// userSelectQop: QOP_TO_FLAG[AUTH] | QOP_TO_FLAG[AUTH_CONF] | QOP_TO_FLAG[AUTH_INT],
		userSelectQop: QOP_TO_FLAG[AUTH],
	}
	return
}

func (m *GSSAPIMechanism) step(challenge []byte) ([]byte, error) {
	if m.negotiationStage == 0 {
		err := InitClientContext(m.context, m.service+"/"+m.host, nil)
		m.negotiationStage = 1
		return m.context.token, err

	} else if m.negotiationStage == 1 {
		err := InitClientContext(m.context, m.service+"/"+m.host, challenge)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}

		var srcName *gssapi.Name
		if m.context.contextId != nil {
			srcName, _, _, _, _, _, _, _ = m.context.contextId.InquireContext()
			if srcName != nil {
				m.user = srcName.String()
			}
		}
		if m.user != "" {
			if !m.context.IntegAvail() && !m.context.ConfAvail() {
				log.Println("No security layer can be established, auth is still possible")
			}
			m.negotiationStage = 2
		}
		return m.context.token, nil
	} else if m.negotiationStage == 2 {
		data, err := m.context.Unwrap(challenge)
		if err != nil {
			return nil, err
		}
		if len(data) != 4 {
			return nil, fmt.Errorf("Decoded data should have length for at this stage")
		}
		qopBits := data[0]
		data[0] = 0
		m.serverMaxLength = int(binary.BigEndian.Uint32(data))
		if m.serverMaxLength == 0 {
			return nil, fmt.Errorf("The maximum packet length can't be zero. The server doesn't support GSSAPI")
		}

		m.qop, err = m.selectQop(qopBits)
		if err != nil {
			m.maxLength = 0
		}

		header := make([]byte, 4)
		maxLength := m.serverMaxLength
		if m.maxLength < m.serverMaxLength {
			maxLength = m.maxLength
		}

		headerInt := (uint(m.qop) << 24) | uint(maxLength)

		binary.BigEndian.PutUint32(header, uint32(headerInt))

		out := append(header, []byte(m.user)...)
		wrappedOut, err := m.context.Wrap(out, false)

		m.mechanismConfig.complete = true
		return wrappedOut, err
	}
	return nil, fmt.Errorf("Error, this code should be unreachable")
}

func (m *GSSAPIMechanism) selectQop(qopByte byte) (byte, error) {
	availableQops := m.userSelectQop & m.supportedQop & qopByte
	for _, qop := range []byte{QOP_TO_FLAG[AUTH_CONF], QOP_TO_FLAG[AUTH_INT], QOP_TO_FLAG[AUTH]} {
		if qop&availableQops != 0 {
			return qop, nil
		}
	}
	return byte(0), fmt.Errorf("No qop satisfying all the conditions where found")
}

// replaceSPNHostWildcard substitutes the special string '_HOST' in the given
// SPN for the given (current) host.
func replaceSPNHostWildcard(spn, host string) string {
	res := krbSPNHost.FindStringSubmatchIndex(spn)
	if res == nil || res[2] == -1 {
		return spn
	}
	return spn[:res[2]] + host + spn[res[3]:]
}

func (m GSSAPIMechanism) wrap(outgoing []byte) ([]byte, error) {
	if m.qop == QOP_TO_FLAG[AUTH] {
		return outgoing, nil
	} else {
		var conf_flag bool = false
		if m.qop == QOP_TO_FLAG[AUTH_CONF] {
			conf_flag = true
		}
		return m.context.Wrap(deepCopy(outgoing), conf_flag)
	}
}

func (m GSSAPIMechanism) unwrap(incoming []byte) ([]byte, error) {
	if m.qop == QOP_TO_FLAG[AUTH] {
		return incoming, nil
	}
	return m.context.Unwrap(deepCopy(incoming))
}

func deepCopy(original []byte) []byte {
	copied := make([]byte, len(original))
	for i, el := range original {
		copied[i] = el
	}
	return copied
}

func (m GSSAPIMechanism) dispose() {
	m.context.Dispose()
}

func (m GSSAPIMechanism) getConfig() *MechanismConfig {
	return m.mechanismConfig
}

// Client is the entry point for usage of this library
type Client struct {
	host            string
	authorizationID string
	mechanism       Mechanism
}

func newDefaultConfig(name string) *MechanismConfig {
	return &MechanismConfig{
		name:               name,
		score:              0,
		complete:           false,
		hasInitialResponse: false,
		allowsAnonymous:    true,
		usesPlaintext:      true,
		activeSafe:         false,
		dictionarySafe:     false,
		qop:                nil,
		authorizationID:    "",
	}
}

// NewSaslClient creates a new Client
func NewSaslClient(host string, mechanismName string, username string, password string) *Client {
	var mechanism Mechanism

	switch mechanismName {
	case "Anonymous":
		mechanism = NewAnonymousMechanism()
	case "NONE":
		mechanism = NewPlainMechanism(username, password)
	case "PLAIN":
		mechanism = NewPlainMechanism(username, password)
	default:
		panic(fmt.Sprintf("Unknown mechanism %s", mechanismName))
	}

	return &Client{
		host:      host,
		mechanism: mechanism,
	}
}

// NewSaslClientWithMechanism accepts the mechanisms and constructs the client from that
func NewSaslClientWithMechanism(host string, mechanism Mechanism) *Client {
	return &Client{
		host:      host,
		mechanism: mechanism,
	}
}

// Process is used for the initial handshake
func (client *Client) Step(challenge []byte) ([]byte, error) {
	return client.mechanism.step(challenge)
}

// Complete returns true if the handshake has ended
func (client *Client) Complete() bool {
	return client.mechanism.getConfig().complete
}

// Wrap is applied on the outgoing bytes to secure them usually
func (client *Client) Wrap(outgoing []byte) ([]byte, error) {
	return client.mechanism.wrap(outgoing)
}

// Unwrap is used on the incoming data to produce the usable bytes
func (client *Client) Unwrap(incoming []byte) ([]byte, error) {
	return client.mechanism.unwrap(incoming)
}

// Dispose eliminates sensitive information
func (client *Client) Dispose() {
	client.mechanism.dispose()
}
