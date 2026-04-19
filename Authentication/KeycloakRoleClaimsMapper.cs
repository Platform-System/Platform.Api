using System.Security.Claims;
using System.Text.Json;

namespace Platform.Api.Authentication;

/// <summary>
/// Chuẩn hóa role từ JWT của Keycloak sang ClaimsIdentity của ASP.NET.
///
/// Lý do cần mapper này:
/// - Keycloak thường không nhét role trực tiếp dưới claim chuẩn "role"
/// - realm role nằm trong "realm_access.roles"
/// - client role nằm trong "resource_access.{client}.roles"
///
/// ASP.NET chỉ dùng [Authorize(Roles = "...")] thuận tiện khi các role
/// đã được add vào ClaimsIdentity dưới RoleClaimType hiện tại.
/// </summary>
public static class KeycloakRoleClaimsMapper
{
    /// <summary>
    /// Entry point được gọi sau khi JWT đã được validate thành công.
    /// Nhiệm vụ là đọc role từ các claim JSON đặc trưng của Keycloak
    /// rồi add lại thành role claim "thật" cho ASP.NET dùng.
    /// </summary>
    public static void Map(ClaimsPrincipal principal)
    {
        if (principal.Identity is not ClaimsIdentity identity)
            return;

        AddRealmRoles(principal, identity);
        AddClientRoles(principal, identity);
    }

    /// <summary>
    /// Đọc realm roles từ claim "realm_access".
    ///
    /// Ví dụ token:
    /// "realm_access": { "roles": ["user", "admin"] }
    /// </summary>
    private static void AddRealmRoles(ClaimsPrincipal principal, ClaimsIdentity identity)
    {
        var realmAccess = principal.FindFirst(PlatformClaimTypes.RealmAccess)?.Value;
        if (string.IsNullOrWhiteSpace(realmAccess))
            return;

        using var document = JsonDocument.Parse(realmAccess);
        if (!document.RootElement.TryGetProperty(PlatformClaimTypes.Roles, out var rolesElement) ||
            rolesElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        AddRoles(identity, rolesElement);
    }

    /// <summary>
    /// Đọc client roles từ claim "resource_access".
    ///
    /// Ví dụ token:
    /// "resource_access": {
    ///   "platform-gateway": { "roles": ["catalog.write"] }
    /// }
    ///
    /// Mapper này quét tất cả client có trong token và add toàn bộ role tìm thấy.
    /// </summary>
    private static void AddClientRoles(ClaimsPrincipal principal, ClaimsIdentity identity)
    {
        var resourceAccess = principal.FindFirst(PlatformClaimTypes.ResourceAccess)?.Value;
        if (string.IsNullOrWhiteSpace(resourceAccess))
            return;

        using var document = JsonDocument.Parse(resourceAccess);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            return;

        foreach (var client in document.RootElement.EnumerateObject())
        {
            if (!client.Value.TryGetProperty(PlatformClaimTypes.Roles, out var rolesElement) ||
                rolesElement.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            AddRoles(identity, rolesElement);
        }
    }

    /// <summary>
    /// Add từng role vào ClaimsIdentity nếu role đó chưa tồn tại.
    ///
    /// Làm vậy để:
    /// - tránh duplicate claim nếu pipeline chạy lặp
    /// - đảm bảo [Authorize(Roles = "...")] đọc được ngay
    /// </summary>
    private static void AddRoles(ClaimsIdentity identity, JsonElement rolesElement)
    {
        foreach (var roleElement in rolesElement.EnumerateArray())
        {
            var role = roleElement.GetString();
            if (string.IsNullOrWhiteSpace(role))
                continue;

            if (!identity.HasClaim(identity.RoleClaimType, role))
            {
                identity.AddClaim(new Claim(identity.RoleClaimType, role));
            }
        }
    }
}
