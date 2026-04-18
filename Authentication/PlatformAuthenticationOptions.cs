namespace Platform.Api.Authentication;

public sealed class PlatformAuthenticationOptions
{
    public required string AuthServerUrl { get; init; }
    public required string Realm { get; init; }
    public required string Resource { get; init; }
    public required bool VerifyTokenAudience { get; init; }
    public required string SslRequired { get; init; }

    public string Authority => $"{AuthServerUrl.TrimEnd('/')}/realms/{Realm}";
    public string MetadataAddress => $"{Authority}/.well-known/openid-configuration";
    public bool RequireHttpsMetadata => !string.Equals(SslRequired, PlatformAuthenticationConstants.SslRequiredNone, StringComparison.OrdinalIgnoreCase);
}
