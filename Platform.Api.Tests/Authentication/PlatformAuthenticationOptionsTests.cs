using Platform.Api.Authentication;
using Xunit;

namespace Platform.Api.Tests.Authentication;

public sealed class PlatformAuthenticationOptionsTests
{
    [Fact]
    public void ComputedProperties_WhenSslRequiredIsNone_ReturnExpectedValues()
    {
        var options = new PlatformAuthenticationOptions
        {
            AuthServerUrl = "http://localhost:8080/",
            Realm = "platform",
            Resource = "gateway",
            VerifyTokenAudience = true,
            SslRequired = "none"
        };

        Assert.Equal("http://localhost:8080/realms/platform", options.Authority);
        Assert.Equal("http://localhost:8080/realms/platform/.well-known/openid-configuration", options.MetadataAddress);
        Assert.False(options.RequireHttpsMetadata);
    }

    [Fact]
    public void ComputedProperties_WhenSslRequiredIsExternal_RequiresHttpsMetadata()
    {
        var options = new PlatformAuthenticationOptions
        {
            AuthServerUrl = "https://auth.example.com",
            Realm = "platform",
            Resource = "gateway",
            VerifyTokenAudience = false,
            SslRequired = "external"
        };

        Assert.True(options.RequireHttpsMetadata);
    }
}
