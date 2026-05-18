using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Platform.Api.Extensions;
using Xunit;

namespace Platform.Api.Tests.Extensions;

public sealed class AuthenticationExtensionsTests
{
    [Fact]
    public void AddPlatformAuthentication_WhenKeycloakConfigMissing_ThrowsInvalidOperationException()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            services.AddPlatformAuthentication(configuration));

        Assert.Contains("Keycloak:auth-server-url is not configured.", exception.Message);
    }
}
