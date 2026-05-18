using Platform.Api.Authentication;
using System.Security.Claims;
using Xunit;

namespace Platform.Api.Tests.Authentication;

public sealed class KeycloakRoleClaimsMapperTests
{
    [Fact]
    public void Map_WhenRealmAndClientRolesExist_AddsDistinctRoleClaims()
    {
        var identity = new ClaimsIdentity([], "Bearer", ClaimTypes.Name, ClaimTypes.Role);
        var principal = new ClaimsPrincipal(identity);
        identity.AddClaim(new Claim(PlatformClaimTypes.RealmAccess, """{"roles":["admin","seller"]}"""));
        identity.AddClaim(new Claim(PlatformClaimTypes.ResourceAccess, """{"gateway":{"roles":["catalog.write","admin"]},"api":{"roles":["seller"]}}"""));

        KeycloakRoleClaimsMapper.Map(principal);

        var roles = principal.FindAll(ClaimTypes.Role).Select(x => x.Value).ToArray();
        Assert.Equal(3, roles.Length);
        Assert.Contains("admin", roles);
        Assert.Contains("seller", roles);
        Assert.Contains("catalog.write", roles);
    }

    [Fact]
    public void Map_WhenCalledTwice_DoesNotDuplicateRoles()
    {
        var identity = new ClaimsIdentity([], "Bearer", ClaimTypes.Name, ClaimTypes.Role);
        var principal = new ClaimsPrincipal(identity);
        identity.AddClaim(new Claim(PlatformClaimTypes.RealmAccess, """{"roles":["admin"]}"""));

        KeycloakRoleClaimsMapper.Map(principal);
        KeycloakRoleClaimsMapper.Map(principal);

        Assert.Single(principal.FindAll(ClaimTypes.Role));
    }
}
