// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "termsOfService": "http://swagger.io/terms/",
        "contact": {
            "name": "Pratik Saha",
            "email": "p.saha@reply.de"
        },
        "license": {
            "name": "Apache 2.0",
            "url": "http://www.apache.org/licenses/LICENSE-2.0.html"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/.well-known/jwks.json": {
            "get": {
                "description": "Returns the RSA public signing keys in JWK format, which can be used to verify JWT signatures.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "keys"
                ],
                "summary": "Retrieve Public Signing Keys",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "object",
                            "additionalProperties": true
                        }
                    },
                    "500": {
                        "description": "Error getting keys\" or \"Error encoding keys",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/introspect": {
            "get": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "Validates a JWT token provided as a query parameter and returns its introspection result including active status and token claims.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "introspection"
                ],
                "summary": "Introspect JWT Token",
                "responses": {
                    "200": {
                        "description": "Token introspection result",
                        "schema": {
                            "$ref": "#/definitions/handlers.IntrospectionResponse"
                        }
                    },
                    "400": {
                        "description": "Missing token parameter",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/token": {
            "get": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "description": "Validates client credentials and returns a JWT token",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "token"
                ],
                "summary": "Generate JWT Token",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/handlers.TokenResponse"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Error generating token",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "handlers.IntrospectionResponse": {
            "type": "object",
            "properties": {
                "active": {
                    "type": "boolean"
                },
                "exp": {
                    "type": "integer"
                },
                "iat": {
                    "type": "integer"
                },
                "iss": {
                    "type": "string"
                },
                "role": {
                    "type": "string"
                },
                "sub": {
                    "type": "string"
                }
            }
        },
        "handlers.TokenResponse": {
            "type": "object",
            "properties": {
                "access_token": {
                    "type": "string"
                },
                "expires_in": {
                    "type": "integer"
                },
                "token_type": {
                    "type": "string"
                }
            }
        }
    },
    "securityDefinitions": {
        "BasicAuth": {
            "type": "basic"
        },
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "localhost:8080",
	BasePath:         "/",
	Schemes:          []string{},
	Title:            "OAuth2 Server API",
	Description:      "This is an OAuth2 server that issues JWT access tokens.",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
