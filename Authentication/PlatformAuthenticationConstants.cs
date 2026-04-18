namespace Platform.Api.Authentication;

public static class PlatformAuthenticationConstants
{
    public const string KeycloakSectionName = "Keycloak";
    public const string AuthServerUrlKey = "auth-server-url";
    public const string RealmKey = "realm";
    public const string ResourceKey = "resource";
    public const string VerifyTokenAudienceKey = "verify-token-audience";
    public const string SslRequiredKey = "ssl-required";

    public const string PreferredUserNameClaim = "preferred_username";
    public const string SslRequiredNone = "none";
}
