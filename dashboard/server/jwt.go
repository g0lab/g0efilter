package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// AuthModeJWT validates a bearer JWT (OIDC/SSO). Reserved for tokens issued by
// an external IdP; see setupJWT for the supported key sources.
const AuthModeJWT = "jwt"

const defaultJWTUsernameClaim = "sub"

var (
	errJWTNoKeySource = errors.New(
		"AUTH_MODE=jwt requires one key source: JWT_SECRET, JWT_PUBLIC_KEY, or JWKS_URL")
	errJWTMultiKeySource = errors.New(
		"AUTH_MODE=jwt: set exactly one of JWT_SECRET, JWT_PUBLIC_KEY, JWKS_URL")
)

// setupJWT builds s.jwtVerify from the configured key source. Called at startup
// (jwt mode only) so a bad key or unreachable JWKS fails closed before serving.
//
//nolint:cyclop,funlen // validation switch + verify closure read best together
func (s *Server) setupJWT(ctx context.Context, cfg Config) error {
	if cfg.AuthMode != AuthModeJWT {
		return nil
	}

	switch countTrue(cfg.JWTSecret != "", cfg.JWTPublicKeyPEM != "", cfg.JWKSURL != "") {
	case 0:
		return errJWTNoKeySource
	case 1:
		// exactly one - proceed
	default:
		return errJWTMultiKeySource
	}

	keyOpt, err := jwtKeyOption(ctx, cfg)
	if err != nil {
		return err
	}

	claim := cfg.JWTUsernameClaim
	if claim == "" {
		claim = defaultJWTUsernameClaim
	}

	validateOpts := []jwt.ValidateOption{}
	if cfg.JWTIssuer != "" {
		validateOpts = append(validateOpts, jwt.WithIssuer(cfg.JWTIssuer))
	}

	if cfg.JWTAudience != "" {
		validateOpts = append(validateOpts, jwt.WithAudience(cfg.JWTAudience))
	}

	s.jwtVerify = func(r *http.Request) (string, bool) {
		raw := tokenFromRequest(r)
		if raw == "" {
			return "", false
		}

		// Parse verifies the signature; WithValidate(true) enforces exp/nbf/iat.
		tok, perr := jwt.Parse([]byte(raw), keyOpt, jwt.WithValidate(true))
		if perr != nil {
			s.logger.Debug("auth.jwt_invalid", "remote", clientIP(r), "error", perr.Error())

			return "", false
		}

		verr := jwt.Validate(tok, validateOpts...)
		if verr != nil {
			s.logger.Debug("auth.jwt_rejected", "remote", clientIP(r), "error", verr.Error())

			return "", false
		}

		var principal string

		gerr := tok.Get(claim, &principal)
		if gerr != nil || principal == "" {
			s.logger.Debug("auth.jwt_missing_claim", "remote", clientIP(r), "claim", claim)

			return "", false
		}

		return principal, true
	}

	return nil
}

// countTrue returns how many of the given booleans are true.
func countTrue(bs ...bool) int {
	n := 0

	for _, b := range bs {
		if b {
			n++
		}
	}

	return n
}

// jwtKeyOption returns the jwt.ParseOption carrying the verification key(s).
//
//nolint:ireturn // jwt.ParseOption is the library's key-injection type
func jwtKeyOption(ctx context.Context, cfg Config) (jwt.ParseOption, error) {
	switch {
	case cfg.JWTSecret != "":
		return jwt.WithKey(jwa.HS256(), []byte(cfg.JWTSecret)), nil

	case cfg.JWTPublicKeyPEM != "":
		return pemKeyOption(cfg.JWTPublicKeyPEM)

	default:
		return jwksKeyOption(ctx, cfg.JWKSURL)
	}
}

// pemKeyOption loads an asymmetric public key from an inline PEM or "@/path".
//
//nolint:ireturn // jwt.ParseOption is the library's key-injection type
func pemKeyOption(pemOrPath string) (jwt.ParseOption, error) {
	data := []byte(pemOrPath)

	if path, ok := strings.CutPrefix(pemOrPath, "@"); ok {
		b, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path, not user input
		if err != nil {
			return nil, fmt.Errorf("read JWT_PUBLIC_KEY file: %w", err)
		}

		data = b
	}

	key, err := jwk.ParseKey(data, jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("parse JWT_PUBLIC_KEY: %w", err)
	}

	// PEM does not encode a JWT algorithm. Prefer an embedded `alg` if the key
	// carries one; otherwise infer it from the key type/curve (deterministic for
	// the RSA/EC/OKP keys we accept).
	alg, ok := key.Algorithm()
	if ok && alg.String() != "" {
		sigAlg, aok := alg.(jwa.SignatureAlgorithm)
		if !aok {
			return nil, fmt.Errorf("JWT_PUBLIC_KEY: %w", errJWTBadAlg)
		}

		return jwt.WithKey(sigAlg, key), nil
	}

	inferred, err := inferSignatureAlg(key)
	if err != nil {
		return nil, fmt.Errorf("JWT_PUBLIC_KEY: %w", err)
	}

	return jwt.WithKey(inferred, key), nil
}

// inferSignatureAlg derives the verification algorithm from a PEM-loaded public
// key: RSA→RS256, Ed25519(OKP)→EdDSA, and EC by curve (P-256→ES256, etc.).
func inferSignatureAlg(key jwk.Key) (jwa.SignatureAlgorithm, error) {
	switch key.KeyType() {
	case jwa.RSA():
		return jwa.RS256(), nil
	case jwa.OKP():
		return jwa.EdDSA(), nil
	case jwa.EC():
		return inferECSignatureAlg(key)
	default:
		return jwa.SignatureAlgorithm{}, fmt.Errorf("%w: key type %s", errJWTBadAlg, key.KeyType())
	}
}

func inferECSignatureAlg(key jwk.Key) (jwa.SignatureAlgorithm, error) {
	ecKey, ok := key.(interface {
		Crv() (jwa.EllipticCurveAlgorithm, bool)
	})
	if !ok {
		return jwa.SignatureAlgorithm{}, errJWTNoAlg
	}

	crv, ok := ecKey.Crv()
	if !ok {
		return jwa.SignatureAlgorithm{}, errJWTNoAlg
	}

	switch crv {
	case jwa.P256():
		return jwa.ES256(), nil
	case jwa.P384():
		return jwa.ES384(), nil
	case jwa.P521():
		return jwa.ES512(), nil
	default:
		return jwa.SignatureAlgorithm{}, fmt.Errorf("%w: curve %s", errJWTBadAlg, crv)
	}
}

var (
	errJWTNoAlg  = errors.New("could not determine key algorithm; use JWKS_URL")
	errJWTBadAlg = errors.New("unsupported JWT key type/algorithm")
)

// jwksKeyOption fetches and caches the IdP's JWKS, refreshing on the interval
// its Cache-Control advertises. Fails startup if the set is unreachable.
//
//nolint:ireturn // jwt.ParseOption is the library's key-injection type
func jwksKeyOption(ctx context.Context, url string) (jwt.ParseOption, error) {
	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("jwks cache: %w", err)
	}

	err = cache.Register(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("register jwks %s: %w", url, err)
	}

	// Prime once so an unreachable/invalid endpoint fails at startup.
	_, err = cache.Lookup(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks %s: %w", url, err)
	}

	cached, err := cache.CachedSet(url)
	if err != nil {
		return nil, fmt.Errorf("jwks cached set: %w", err)
	}

	return jwt.WithKeySet(cached), nil
}

// tokenFromRequest pulls a JWT from the Authorization header or a "jwt" cookie.
func tokenFromRequest(r *http.Request) string {
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.EqualFold(bearer[:7], "Bearer ") {
		return bearer[7:]
	}

	cookie, err := r.Cookie("jwt")
	if err != nil {
		return ""
	}

	return cookie.Value
}
