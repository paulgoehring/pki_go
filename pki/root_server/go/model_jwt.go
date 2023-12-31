/*
 * pki.in GO
 *
 * pki in API docs
 *
 * API version: 1.0.0
 * Contact: paul.goehring@student.uni-tuebingen.de
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type Jwt struct {
	// key type
	Kty string `json:"kty,omitempty"`
	// issuer
	Iss string `json:"iss,omitempty"`
	// expiration date
	Exp string `json:"exp,omitempty"`
	// key id of server key which signs jwt
	Kid string `json:"kid,omitempty"`

	Jwk *Jwk `json:"jwk,omitempty"`
}
