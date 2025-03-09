package handlers

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/regulation"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/valyala/fasthttp"
	"gopkg.in/jcmturner/goidentity.v3"
	"gopkg.in/jcmturner/gokrb5.v7/gssapi"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
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
func FirstFactorSPNEGO(inner fasthttp.RequestHandler) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		var (
			details *authentication.UserDetails
			err     error
		)

		// getting the spnego headers
		headerParts := strings.SplitN(string(ctx.Request.Header.Peek(spnego.HTTPHeaderAuthRequest)), " ", 2)
		if len(headerParts) != 2 || headerParts[0] != spnego.HTTPHeaderAuthResponseValueKey {
			// No Authorization header set so return 401 with WWW-Authenticate Negotiate header
			ctx.Response.Header.Set(spnego.HTTPHeaderAuthResponse, spnego.HTTPHeaderAuthResponseValueKey)
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetJSONError(messageMFAValidationFailed)

			ctx.Logger.WithError(err).Errorf(logFmtErrPasskeyAuthenticationChallengeValidate, errStrReqBodyParse)

			doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(regulation.BanTypeNone, "", nil), regulation.AuthTypePasskey, nil)

			return
		}

		bodyJSON := bodyFirstFactorSPNEGOequest{}
		if err = ctx.ParseBody(&bodyJSON); err != nil {
			ctx.Logger.WithError(err).Errorf(logFmtErrParseRequestBody, regulation.AuthType1FA)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		// we then decode the base64-encoded token
		b, err := base64.StdEncoding.DecodeString(headerParts[1])
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.Logger.WithError(err).Errorf(logFmtErrPasskeyAuthenticationChallengeValidate, errStrReqBodyParse)

			doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(regulation.BanTypeNone, "", nil), regulation.AuthTypePasskey, nil)

			return
		}
		// and unmarshal it using the spnego library
		var st spnego.SPNEGOToken
		err = st.Unmarshal(b)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetJSONError(messageAuthenticationFailed)
			ctx.Logger.WithError(err).Errorf(logFmtErrPasskeyAuthenticationChallengeValidate, errStrReqBodyParse)

			doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(regulation.BanTypeNone, "", nil), regulation.AuthTypePasskey, nil)

			return
		}

		SPNEGO, err := ctx.GetSPNEGOProvider()
		if err != nil {
			ctx.Logger.WithError(err).Errorf(logFmtErrPasskeyAuthenticationChallengeGenerate, "error occurred provisioning the configuration")

			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetJSONError(messageMFAValidationFailed)
			doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(regulation.BanTypeNone, "", nil), regulation.AuthTypePasskey, nil)

			return
		}

		// Validate the context token
		authed, context, status := SPNEGO.AcceptSecContext(&st)
		if status.Code != gssapi.StatusComplete && status.Code != gssapi.StatusContinueNeeded {
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetJSONError(messageMFAValidationFailed)
			return
		}

		if status.Code == gssapi.StatusContinueNeeded {
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetJSONError(messageMFAValidationFailed)
			return
		}

		if !authed {

			doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(regulation.BanTypeNone, details.Username, nil), regulation.AuthType1FA, nil)

			respondUnauthorized(ctx, messageAuthenticationFailed)
		}

		authContext := context.Value(spnego.CTXKeyCredentials).(goidentity.Identity)
		ctx.Response.Header.Set(spnego.HTTPHeaderAuthResponse, spnegoNegTokenRespKRBAcceptCompleted)

		username := authContext.UserName()

		if details, err = ctx.Providers.UserProvider.GetDetails(username); err != nil {
			ctx.Logger.WithError(err).Errorf("Error occurred getting details for user with username input '%s' which usually indicates they do not exist", username)

			respondUnauthorized(ctx, messageAuthenticationFailed)
			return

		}

		if ban, _, expires, err := ctx.Providers.Regulator.BanCheck(ctx, details.Username); err != nil {
			if errors.Is(err, regulation.ErrUserIsBanned) {
				doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(ban, details.Username, expires), regulation.AuthType1FA, nil)

				respondUnauthorized(ctx, messageAuthenticationFailed)

				return
			}

			ctx.Logger.WithError(err).Errorf(logFmtErrRegulationFail, regulation.AuthType1FA, details.Username)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		doMarkAuthenticationAttempt(ctx, true, regulation.NewBan(regulation.BanTypeNone, details.Username, nil), regulation.AuthType1FA, nil)

		var provider *session.Session

		if provider, err = ctx.GetSessionProvider(); err != nil {
			ctx.Logger.WithError(err).Error("Failed to get session provider during 1FA attempt")

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		if err = provider.DestroySession(ctx.RequestCtx); err != nil {
			// This failure is not likely to be critical as we ensure to regenerate the session below.
			ctx.Logger.WithError(err).Trace("Failed to destroy session during 1FA attempt")
		}

		userSession := provider.NewDefaultUserSession()

		// Reset all values from previous session except OIDC workflow before regenerating the cookie.
		if err = provider.SaveSession(ctx.RequestCtx, userSession); err != nil {
			ctx.Logger.WithError(err).Errorf(logFmtErrSessionReset, regulation.AuthType1FA, details.Username)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		if err = provider.RegenerateSession(ctx.RequestCtx); err != nil {
			ctx.Logger.WithError(err).Errorf(logFmtErrSessionRegenerate, regulation.AuthType1FA, details.Username)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		ctx.Logger.Tracef(logFmtTraceProfileDetails, details.Username, details.Groups, details.Emails)

		userSession.SetOneFactorPassword(ctx.Clock.Now(), details, false)

		if ctx.Configuration.AuthenticationBackend.RefreshInterval.Update() {
			userSession.RefreshTTL = ctx.Clock.Now().Add(ctx.Configuration.AuthenticationBackend.RefreshInterval.Value())
		}
		if err = provider.SaveSession(ctx.RequestCtx, userSession); err != nil {
			ctx.Logger.WithError(err).Errorf(logFmtErrSessionSave, "updated profile", regulation.AuthType1FA, logFmtActionAuthentication, details.Username)

			respondUnauthorized(ctx, messageAuthenticationFailed)

			return
		}

		if bodyJSON.Workflow == workflowOpenIDConnect {
			handleOIDCWorkflowResponse(ctx, &userSession, bodyJSON.WorkflowID)
		} else {
			Handle1FAResponse(ctx, bodyJSON.TargetURL, bodyJSON.RequestMethod, userSession.Username, userSession.Groups)
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
