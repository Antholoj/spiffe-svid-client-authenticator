# SPIFFE SVID Client Authenticator for Keycloak

This is a custom Keycloak Client Authenticator that validates SPIFFE SVID JWTs for client authentication. It's modeled after the existing JWT client authenticator but specifically designed for SPIFFE SVID validation.

## Features

- Validates SPIFFE SVID JWTs for client authentication
- Follows the same validation patterns as the standard JWT client authenticator
- Provider ID: `client-spiffe-jwt`

## Building

To build the project:

```bash
mvn clean package
```

This will create a JAR file in the `target/` directory.

## Deployment

### Option 1: JAR Deployment (Recommended)

1. Copy the generated JAR from `target/spiffe-svid-client-authenticator-1.0.0.jar` to your Keycloak installation's `providers/` directory
2. Restart Keycloak

### Option 2: Module Deployment

1. Create a JBoss/WildFly module structure
2. Deploy as a module in Keycloak's module system

## Configuration

After deployment:

1. Go to Keycloak Admin Console
2. Navigate to Clients → [Your Client] → Settings
3. Set "Client authentication" to "On"
4. Go to Credentials tab
5. Set "Client authenticator" to "SPIFFE SVID JWT"

## Customization

This authenticator is designed to be easily customizable. You can modify:

- `SpiffeSvidClientAuthenticator.java` - Main authentication logic
- `SpiffeSvidClientValidator.java` - JWT validation logic
- `SpiffeSvidClientAuthUtil.java` - Error response handling

## Dependencies

- Keycloak 26.2.5
- Java 17
- Maven 3.6+

## License

Apache License 2.0 