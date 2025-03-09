package handlers

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/valyala/fasthttp"
	"gopkg.in/jcmturner/goidentity.v3"
	"gopkg.in/jcmturner/gokrb5.v7/gssapi"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/service"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
	"gopkg.in/jcmturner/gokrb5.v7/types"
)

const (
	// spnegoNegTokenRespKRBAcceptCompleted - The response on successful authentication always has this header. Capturing as const so we don't have marshaling and encoding overhead.
	spnegoNegTokenRespKRBAcceptCompleted = "Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
	// spnegoNegTokenRespReject - The response on a failed authentication always has this rejection header. Capturing as const so we don't have marshaling and encoding overhead.
	spnegoNegTokenRespReject = "Negotiate oQcwBaADCgEC"
	// spnegoNegTokenRespIncompleteKRB5 - Response token specifying incomplete context and KRB5 as the supported mechtype.
	spnegoNegTokenRespIncompleteKRB5 = "Negotiate oRQwEqADCgEBoQsGCSqGSIb3EgECAg=="
)

// spnego.SPNEGOKRB5Authenticate is a Kerberos spnego.SPNEGO authentication HTTP handler wrapper.
func FirstFactorSPNEGO(inner fasthttp.RequestHandler, kt *keytab.Keytab, settings ...func(*service.Settings)) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		// Get the auth header
		s := strings.SplitN(string(ctx.Request.Header.Peek(spnego.HTTPHeaderAuthRequest)), " ", 2)
		if len(s) != 2 || s[0] != spnego.HTTPHeaderAuthResponseValueKey {
			// No Authorization header set so return 401 with WWW-Authenticate Negotiate header
			ctx.Response.Header.Set(spnego.HTTPHeaderAuthResponse, spnego.HTTPHeaderAuthResponseValueKey)
			ctx.Response.SetStatusCode(http.StatusUnauthorized)
			ctx.Response.SetBodyString(spnego.UnauthorizedMsg)
			return
		}

		// Set up the spnego.SPNEGO GSS-API mechanism
		var SPNEGO *spnego.SPNEGO
		h, err := types.GetHostAddress(ctx.RemoteAddr().String())
		if err == nil {
			// put in this order so that if the user provides a ClientAddress it will override the one here.
			o := append([]func(*service.Settings){service.ClientAddress(h)}, settings...)
			SPNEGO = spnego.SPNEGOService(kt, o...)
		} else {
			SPNEGO = spnego.SPNEGOService(kt, settings...)
			SPNEGO.Log("%s - spnego.SPNEGO could not parse client address: %v", ctx.RemoteAddr(), err)
		}

		// Decode the header into an spnego.SPNEGO context token
		b, err := base64.StdEncoding.DecodeString(s[1])
		if err != nil {
			SPNEGONegotiateKRB5MechType(SPNEGO, ctx, "%s - spnego.SPNEGO error in base64 decoding negotiation header: %v", ctx.RemoteAddr(), err)
			return
		}
		var st spnego.SPNEGOToken
		err = st.Unmarshal(b)
		if err != nil {
			SPNEGONegotiateKRB5MechType(SPNEGO, ctx, "%s - spnego.SPNEGO error in unmarshaling spnego.SPNEGO token: %v", ctx.RemoteAddr(), err)
			return
		}

		// Validate the context token
		authed, context, status := SPNEGO.AcceptSecContext(&st)
		if status.Code != gssapi.StatusComplete && status.Code != gssapi.StatusContinueNeeded {
			SPNEGOResponseReject(SPNEGO, ctx, "%s - spnego.SPNEGO validation error: %v", ctx.RemoteAddr(), status)
			return
		}

		if status.Code == gssapi.StatusContinueNeeded {
			SPNEGONegotiateKRB5MechType(SPNEGO, ctx, "%s - spnego.SPNEGO GSS-API continue needed", ctx.RemoteAddr())
			return
		}

		if authed {
			_ = context.Value(spnego.CTXKeyCredentials).(goidentity.Identity)

			ctx.Response.Header.Set(spnego.HTTPHeaderAuthResponse, spnegoNegTokenRespKRBAcceptCompleted)

		} else {
			SPNEGOResponseReject(SPNEGO, ctx, "%s - spnego.SPNEGO Kerberos authentication failed", ctx.RemoteAddr())
			return
		}
	}
}

func SPNEGONegotiateKRB5MechType(s *spnego.SPNEGO, ctx *middlewares.AutheliaCtx, format string, v ...interface{}) {
	s.Log(format, v...)
	ctx.Response.Header.Set(spnego.HTTPHeaderAuthResponse, spnegoNegTokenRespIncompleteKRB5)
	ctx.Response.SetStatusCode(http.StatusUnauthorized)
	ctx.Response.SetBodyString(spnego.UnauthorizedMsg)
}

func SPNEGOResponseReject(s *spnego.SPNEGO, ctx *middlewares.AutheliaCtx, format string, v ...interface{}) {
	s.Log(format, v...)
	ctx.Response.Header.Set(spnego.HTTPHeaderAuthResponse, spnegoNegTokenRespReject)
	ctx.Response.SetStatusCode(http.StatusUnauthorized)
	ctx.Response.SetBodyString(spnego.UnauthorizedMsg)
}
