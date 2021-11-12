package soap2

import (
	"encoding/xml"
	"time"

	"github.com/hooklift/gowsdl/soap/share"
)

//  ---------- wsse  ----------

const (
	// Predefined WSS namespaces to be used in
	WssNsWSSE    string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	WssNsWSU     string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	WssNsType    string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
	WssNonceType string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)

type WSSSecurityHeader struct {
	XMLName   xml.Name `xml:"wsse:Security"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`
	XmlNSWsu  string   `xml:"xmlns:wsu,attr"`

	MustUnderstand string `xml:"soap:mustUnderstand,attr,omitempty"`

	Token *WSSUsernameToken `xml:",omitempty"`
}

type WSSUsernameToken struct {
	XMLName xml.Name `xml:"wsse:UsernameToken"`

	Id string `xml:"wsu:Id,attr,omitempty"`

	Username *WSSUsername `xml:",omitempty"`
	Password *WSSPassword `xml:",omitempty"`
	Nonce    *WSSNonce    `xml:",omitempty"`
	Created  string       `xml:"wsu:Created,omitempty"`
}

type WSSNonce struct {
	XMLName      xml.Name `xml:"wsse:Nonce"`
	EncodingType string   `xml:"EncodingType,attr"`

	Data string `xml:",chardata"`
}

type WSSUsername struct {
	XMLName xml.Name `xml:"wsse:Username"`

	Data string `xml:",chardata"`
}

type WSSPassword struct {
	XMLName   xml.Name `xml:"wsse:Password"`
	XmlNSType string   `xml:"Type,attr"`

	Data string `xml:",chardata"`
}

// NewWSSSecurityHeader creates WSSSecurityHeader instance soap1.2
func NewWSSSecurityHeader(user, pass, tokenID, mustUnderstand, nonce string) *WSSSecurityHeader {
	hdr := &WSSSecurityHeader{XmlNSWsse: WssNsWSSE, XmlNSWsu: WssNsWSU, MustUnderstand: mustUnderstand}
	hdr.Token = &WSSUsernameToken{Id: tokenID}
	hdr.Token.Username = &WSSUsername{Data: user}
	hdr.Token.Password = &WSSPassword{XmlNSType: WssNsType, Data: pass}
	hdr.Token.Nonce = &WSSNonce{EncodingType: WssNonceType, Data: nonce}
	// hdr.Token.Created = "2021-11-12T03:43:21.425Z"
	hdr.Token.Created = time.Now().Format("2006-01-02T15:04:05.999Z")
	return hdr
}

//  ---------- wsse  ----------

const (
	XmlNsSoapEnv string = "http://www.w3.org/2003/05/soap-envelope"
	ContentType  string = "application/soap+xml;charset=UTF-8"
)

type SOAPEnvelopeResponse struct {
	XMLName     xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
	Header      *SOAPHeaderResponse
	Body        SOAPBodyResponse
	Attachments []share.MIMEMultipartAttachment `xml:"attachments,omitempty"`
}

type SOAPEnvelope struct {
	XMLName xml.Name `xml:"soap:Envelope"`
	XmlNS   string   `xml:"xmlns:soap,attr"`
	XmlUrn  string   `xml:"xmlns:urn,attr"`

	Header *SOAPHeader
	Body   SOAPBody
}

type SOAPHeader struct {
	XMLName xml.Name `xml:"soap:Header"`

	Headers []interface{}
}
type SOAPHeaderResponse struct {
	XMLName xml.Name `xml:"Header"`

	Headers []interface{}
}

type SOAPBody struct {
	XMLName xml.Name `xml:"soap:Body"`

	Content interface{} `xml:",omitempty"`

	// faultOccurred indicates whether the XML body included a fault;
	// we cannot simply store SOAPFault as a pointer to indicate this, since
	// fault is initialized to non-nil with user-provided detail type.
	faultOccurred bool
	Fault         *SOAPFault `xml:",omitempty"`
}

type SOAPBodyResponse struct {
	XMLName xml.Name `xml:"Body"`

	Content interface{} `xml:",omitempty"`

	// faultOccurred indicates whether the XML body included a fault;
	// we cannot simply store SOAPFault as a pointer to indicate this, since
	// fault is initialized to non-nil with user-provided detail type.
	faultOccurred bool
	Fault         *SOAPFault `xml:",omitempty"`
}

// UnmarshalXML unmarshals SOAPBody xml
func (b *SOAPBodyResponse) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}

	var (
		token    xml.Token
		err      error
		consumed bool
	)

Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}

		if token == nil {
			break
		}

		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError("Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Space == XmlNsSoapEnv && se.Name.Local == "Fault" {
				b.Content = nil

				b.faultOccurred = true
				err = d.DecodeElement(b.Fault, &se)
				if err != nil {
					return err
				}

				consumed = true
			} else {
				if err = d.DecodeElement(b.Content, &se); err != nil {
					return err
				}

				consumed = true
			}
		case xml.EndElement:
			break Loop
		}
	}

	return nil
}

func (b *SOAPBody) ErrorFromFault() error {
	if b.faultOccurred {
		return b.Fault
	}
	b.Fault = nil
	return nil
}

func (b *SOAPBodyResponse) ErrorFromFault() error {
	if b.faultOccurred {
		return b.Fault
	}
	b.Fault = nil
	return nil
}

type DetailContainer struct {
	Detail interface{}
}

type FaultError interface {
	// ErrorString should return a short version of the detail as a string,
	// which will be used in place of <faultstring> for the error message.
	// Set "HasData()" to always return false if <faultstring> error
	// message is preferred.
	ErrorString() string
	// HasData indicates whether the composite fault contains any data.
	HasData() bool
}

type SOAPFault struct {
	XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Fault"`

	Code   string     `xml:"faultcode,omitempty"`
	String string     `xml:"faultstring,omitempty"`
	Actor  string     `xml:"faultactor,omitempty"`
	Detail FaultError `xml:"detail,omitempty"`
}

func (f *SOAPFault) Error() string {
	if f.Detail != nil && f.Detail.HasData() {
		return f.Detail.ErrorString()
	}
	return f.String
}
