package soap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/hooklift/gowsdl/soap/share"
	"github.com/hooklift/gowsdl/soap/soap1"
	"github.com/hooklift/gowsdl/soap/soap2"
)

type SOAPEncoder interface {
	Encode(v interface{}) error
	Flush() error
}

type SOAPDecoder interface {
	Decode(v interface{}) error
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

// HTTPError is returned whenever the HTTP request to the server fails
type HTTPError struct {
	//StatusCode is the status code returned in the HTTP response
	StatusCode int
	//ResponseBody contains the body returned in the HTTP response
	ResponseBody []byte
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP Status %d: %s", e.StatusCode, string(e.ResponseBody))
}

type basicAuth struct {
	Login    string
	Password string
}

type options struct {
	tlsCfg           *tls.Config
	auth             *basicAuth
	timeout          time.Duration
	contimeout       time.Duration
	tlshshaketimeout time.Duration
	client           HTTPClient
	httpHeaders      map[string]string
	mtom             bool
	mma              bool
	soapVersion      string
	debug            bool
}

var defaultOptions = options{
	timeout:          time.Duration(30 * time.Second),
	contimeout:       time.Duration(90 * time.Second),
	tlshshaketimeout: time.Duration(15 * time.Second),
}

// A Option sets options such as credentials, tls, etc.
type Option func(*options)

func WithDebug(debug bool) Option {
	return func(o *options) {
		o.debug = debug
	}
}

// soap version 1.1 or 1.2
func WithSoapVersion(version string) Option {
	return func(o *options) {
		o.soapVersion = version
	}
}

// WithHTTPClient is an Option to set the HTTP client to use
// This cannot be used with WithTLSHandshakeTimeout, WithTLS,
// WithTimeout options
func WithHTTPClient(c HTTPClient) Option {
	return func(o *options) {
		o.client = c
	}
}

// WithTLSHandshakeTimeout is an Option to set default tls handshake timeout
// This option cannot be used with WithHTTPClient
func WithTLSHandshakeTimeout(t time.Duration) Option {
	return func(o *options) {
		o.tlshshaketimeout = t
	}
}

// WithRequestTimeout is an Option to set default end-end connection timeout
// This option cannot be used with WithHTTPClient
func WithRequestTimeout(t time.Duration) Option {
	return func(o *options) {
		o.contimeout = t
	}
}

// WithBasicAuth is an Option to set BasicAuth
func WithBasicAuth(login, password string) Option {
	return func(o *options) {
		o.auth = &basicAuth{Login: login, Password: password}
	}
}

// WithTLS is an Option to set tls config
// This option cannot be used with WithHTTPClient
func WithTLS(tls *tls.Config) Option {
	return func(o *options) {
		o.tlsCfg = tls
	}
}

// WithTimeout is an Option to set default HTTP dial timeout
func WithTimeout(t time.Duration) Option {
	return func(o *options) {
		o.timeout = t
	}
}

// WithHTTPHeaders is an Option to set global HTTP headers for all requests
func WithHTTPHeaders(headers map[string]string) Option {
	return func(o *options) {
		o.httpHeaders = headers
	}
}

// WithMTOM is an Option to set Message Transmission Optimization Mechanism
// MTOM encodes fields of type Binary using XOP.
func WithMTOM() Option {
	return func(o *options) {
		o.mtom = true
	}
}

// WithMIMEMultipartAttachments is an Option to set SOAP MIME Multipart attachment support.
// Use Client.AddMIMEMultipartAttachment to add attachments of type MIMEMultipartAttachment to your SOAP request.
func WithMIMEMultipartAttachments() Option {
	return func(o *options) {
		o.mma = true
	}
}

// Client is soap client
type Client struct {
	url         string
	opts        *options
	headers     []interface{}
	attachments []share.MIMEMultipartAttachment
}

// HTTPClient is a client which can make HTTP requests
// An example implementation is net/http.Client
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// NewClient creates new SOAP client instance
func NewClient(url string, opt ...Option) *Client {
	opts := defaultOptions
	for _, o := range opt {
		o(&opts)
	}
	return &Client{
		url:  url,
		opts: &opts,
	}
}

// AddHeader adds envelope header
// For correct behavior, every header must contain a `XMLName` field.  Refer to #121 for details
func (s *Client) AddHeader(header interface{}) {
	s.headers = append(s.headers, header)
}

// AddMIMEMultipartAttachment adds an attachment to the client that will be sent only if the
// WithMIMEMultipartAttachments option is used
func (s *Client) AddMIMEMultipartAttachment(attachment share.MIMEMultipartAttachment) {
	s.attachments = append(s.attachments, attachment)
}

// SetHeaders sets envelope headers, overwriting any existing headers.
// For correct behavior, every header must contain a `XMLName` field.  Refer to #121 for details
func (s *Client) SetHeaders(headers ...interface{}) {
	s.headers = headers
}

// CallContext performs HTTP POST request with a context
func (s *Client) CallContext(ctx context.Context, soapAction string, request, response interface{}) error {
	return s.call(ctx, soapAction, request, response, nil, nil)
}

// Call performs HTTP POST request.
// Note that if the server returns a status code >= 400, a HTTPError will be returned
func (s *Client) Call(soapAction string, request, response interface{}) error {
	return s.call(context.Background(), soapAction, request, response, nil, nil)
}

// CallContextWithAttachmentsAndFaultDetail performs HTTP POST request.
// Note that if SOAP fault is returned, it will be stored in the error.
// On top the attachments array will be filled with attachments returned from the SOAP request.
func (s *Client) CallContextWithAttachmentsAndFaultDetail(ctx context.Context, soapAction string, request,
	response interface{}, faultDetail FaultError, attachments *[]share.MIMEMultipartAttachment) error {
	return s.call(ctx, soapAction, request, response, faultDetail, attachments)
}

// CallContextWithFault performs HTTP POST request.
// Note that if SOAP fault is returned, it will be stored in the error.
func (s *Client) CallContextWithFaultDetail(ctx context.Context, soapAction string, request, response interface{}, faultDetail FaultError) error {
	return s.call(ctx, soapAction, request, response, faultDetail, nil)
}

// CallWithFaultDetail performs HTTP POST request.
// Note that if SOAP fault is returned, it will be stored in the error.
// the passed in fault detail is expected to implement FaultError interface,
// which allows to condense the detail into a short error message.
func (s *Client) CallWithFaultDetail(soapAction string, request, response interface{}, faultDetail FaultError) error {
	return s.call(context.Background(), soapAction, request, response, faultDetail, nil)
}

func (s *Client) call(ctx context.Context, soapAction string, request, response interface{}, faultDetail FaultError,
	retAttachments *[]share.MIMEMultipartAttachment) error {
	if s.opts.soapVersion == "1.2" {
		return s.callVersion2(ctx, soapAction, request, response, faultDetail, retAttachments)
	} else {
		return s.callVersion1(ctx, soapAction, request, response, faultDetail, retAttachments)
	}
}

func (s *Client) callVersion1(ctx context.Context, soapAction string, request, response interface{}, faultDetail FaultError,
	retAttachments *[]share.MIMEMultipartAttachment) error {

	if s.opts.debug {
		log.Println("we do soap1.1 now")
	}
	// SOAP envelope capable of namespace prefixes
	envelope := &soap1.SOAPEnvelope{
		XmlNS: soap1.XmlNsSoapEnv,
	}

	if s.headers != nil && len(s.headers) > 0 {
		envelope.Header = &soap1.SOAPHeader{
			Headers: s.headers,
		}
	}

	envelope.Body.Content = request
	buffer := new(bytes.Buffer)
	var encoder SOAPEncoder
	if s.opts.mtom && s.opts.mma {
		return fmt.Errorf("cannot use MTOM (XOP) and MMA (MIME Multipart Attachments) option at the same time")
	} else if s.opts.mtom {
		encoder = share.NewMtomEncoder(buffer)
	} else if s.opts.mma {
		encoder = share.NewMmaEncoder(buffer, s.attachments)
	} else {
		encoder = xml.NewEncoder(buffer)
	}

	if err := encoder.Encode(envelope); err != nil {
		return err
	}

	if err := encoder.Flush(); err != nil {
		return err
	}
	if s.opts.debug {
		log.Println(buffer.String())
	}

	req, err := http.NewRequest("POST", s.url, buffer)
	if err != nil {
		return err
	}
	if s.opts.auth != nil {
		req.SetBasicAuth(s.opts.auth.Login, s.opts.auth.Password)
	}

	req = req.WithContext(ctx)

	if s.opts.mtom {
		req.Header.Add("Content-Type", fmt.Sprintf(share.MtomContentType, encoder.(*share.MtomEncoder).Boundary()))
	} else if s.opts.mma {
		req.Header.Add("Content-Type", fmt.Sprintf(share.MmaContentType, encoder.(*share.MmaEncoder).Boundary()))
	} else {
		req.Header.Add("Content-Type", soap1.ContentType)
	}
	req.Header.Add("SOAPAction", soapAction)
	req.Header.Set("User-Agent", "gowsdl")
	if s.opts.httpHeaders != nil {
		for k, v := range s.opts.httpHeaders {
			req.Header.Set(k, v)
		}
	}
	req.Close = true

	client := s.opts.client
	if client == nil {
		tr := &http.Transport{
			TLSClientConfig: s.opts.tlsCfg,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := net.Dialer{Timeout: s.opts.timeout}
				return d.DialContext(ctx, network, addr)
			},
			TLSHandshakeTimeout: s.opts.tlshshaketimeout,
		}
		client = &http.Client{Timeout: s.opts.contimeout, Transport: tr}
	}
	if s.opts.debug {
		log.Println("request to url: ", req.URL.String())
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		body, _ := ioutil.ReadAll(res.Body)
		return &HTTPError{
			StatusCode:   res.StatusCode,
			ResponseBody: body,
		}
	}

	// xml Decoder (used with and without MTOM) cannot handle namespace prefixes (yet),
	// so we have to use a namespace-less response envelope
	respEnvelope := new(soap1.SOAPEnvelopeResponse)
	respEnvelope.Body = soap1.SOAPBodyResponse{
		Content: response,
		Fault: &soap1.SOAPFault{
			Detail: faultDetail,
		},
	}

	mtomBoundary, err := share.GetMtomHeader(res.Header.Get("Content-Type"))
	if err != nil {
		return err
	}

	var mmaBoundary string
	if s.opts.mma {
		mmaBoundary, err = share.GetMmaHeader(res.Header.Get("Content-Type"))
		if err != nil {
			return err
		}
	}

	var dec SOAPDecoder
	if mtomBoundary != "" {
		dec = share.NewMtomDecoder(res.Body, mtomBoundary)
	} else if mmaBoundary != "" {
		dec = share.NewMmaDecoder(res.Body, mmaBoundary)
	} else {
		dec = xml.NewDecoder(res.Body)

	}
	if err := dec.Decode(respEnvelope); err != nil {
		return err
	}

	if respEnvelope.Attachments != nil {
		*retAttachments = respEnvelope.Attachments
	}
	return respEnvelope.Body.ErrorFromFault()
}

func (s *Client) callVersion2(ctx context.Context, soapAction string, request, response interface{}, faultDetail FaultError,
	retAttachments *[]share.MIMEMultipartAttachment) error {

	if s.opts.debug {
		log.Println("we do soap1.2 now")
	}
	// SOAP envelope capable of namespace prefixes
	//TODO: XmlUrn
	envelope := soap2.SOAPEnvelope{
		XmlNS:  soap2.XmlNsSoapEnv,
		XmlUrn: "",
	}

	if s.headers != nil && len(s.headers) > 0 {
		envelope.Header = &soap2.SOAPHeader{
			Headers: s.headers,
		}
	}

	envelope.Body.Content = request
	buffer := new(bytes.Buffer)
	var encoder SOAPEncoder
	if s.opts.mtom && s.opts.mma {
		return fmt.Errorf("cannot use MTOM (XOP) and MMA (MIME Multipart Attachments) option at the same time")
	} else if s.opts.mtom {
		encoder = share.NewMtomEncoder(buffer)
	} else if s.opts.mma {
		encoder = share.NewMmaEncoder(buffer, s.attachments)
	} else {
		encoder = xml.NewEncoder(buffer)
	}

	if err := encoder.Encode(envelope); err != nil {
		return err
	}

	if err := encoder.Flush(); err != nil {
		return err
	}
	if s.opts.debug {
		log.Println(buffer.String())
	}

	req, err := http.NewRequest("POST", s.url, buffer)
	if err != nil {
		return err
	}
	if s.opts.auth != nil {
		req.SetBasicAuth(s.opts.auth.Login, s.opts.auth.Password)
	}

	req = req.WithContext(ctx)

	if s.opts.mtom {
		req.Header.Add("Content-Type", fmt.Sprintf(share.MtomContentType, encoder.(*share.MtomEncoder).Boundary()))
	} else if s.opts.mma {
		req.Header.Add("Content-Type", fmt.Sprintf(share.MmaContentType, encoder.(*share.MmaEncoder).Boundary()))
	} else {
		if soapAction != "" {
			req.Header.Add("Content-Type", soap2.ContentType+fmt.Sprintf(`;action="%s"`, soapAction))
		} else {
			req.Header.Add("Content-Type", soap2.ContentType)
		}

	}

	req.Header.Set("User-Agent", "gowsdl")
	if s.opts.httpHeaders != nil {
		for k, v := range s.opts.httpHeaders {
			req.Header.Set(k, v)
		}
	}
	req.Close = true

	client := s.opts.client
	if client == nil {
		tr := &http.Transport{
			TLSClientConfig: s.opts.tlsCfg,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := net.Dialer{Timeout: s.opts.timeout}
				return d.DialContext(ctx, network, addr)
			},
			TLSHandshakeTimeout: s.opts.tlshshaketimeout,
		}
		client = &http.Client{Timeout: s.opts.contimeout, Transport: tr}
	}

	if s.opts.debug {
		log.Println("request to url: ", req.URL.String())
	}

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		body, _ := ioutil.ReadAll(res.Body)
		return &HTTPError{
			StatusCode:   res.StatusCode,
			ResponseBody: body,
		}
	}

	// xml Decoder (used with and without MTOM) cannot handle namespace prefixes (yet),
	// so we have to use a namespace-less response envelope
	respEnvelope := new(soap2.SOAPEnvelopeResponse)
	respEnvelope.Body = soap2.SOAPBodyResponse{
		Content: response,
		Fault: &soap2.SOAPFault{
			Detail: faultDetail,
		},
	}

	mtomBoundary, err := share.GetMtomHeader(res.Header.Get("Content-Type"))
	if err != nil {
		return err
	}

	var mmaBoundary string
	if s.opts.mma {
		mmaBoundary, err = share.GetMmaHeader(res.Header.Get("Content-Type"))
		if err != nil {
			return err
		}
	}

	var dec SOAPDecoder
	if mtomBoundary != "" {
		dec = share.NewMtomDecoder(res.Body, mtomBoundary)
	} else if mmaBoundary != "" {
		dec = share.NewMmaDecoder(res.Body, mmaBoundary)
	} else {
		dec = xml.NewDecoder(res.Body)
	}
	//need to remove <?xml version=\"1.0\" encoding=\"UTF-8\"?></xml>
	if err := dec.Decode(respEnvelope); err != nil {
		return err
	}

	if respEnvelope.Attachments != nil {
		*retAttachments = respEnvelope.Attachments
	}
	return respEnvelope.Body.ErrorFromFault()
}
