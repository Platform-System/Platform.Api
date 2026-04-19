using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Platform.Api.Authentication;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Platform.Api.Extensions;

public static class AuthenticationExtensions
{
    public static IServiceCollection AddPlatformAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        // Đọc toàn bộ cấu hình auth từ appsettings rồi gom về object options.
        // Làm vậy giúp đoạn AddJwtBearer phía dưới ngắn và dễ đọc hơn.
        var authOptions = configuration.GetPlatformAuthenticationOptions();

        // Tắt mapping claim mặc định của .NET để ta đọc đúng tên claim gốc trong JWT.
        // Ví dụ: claim "sub" sẽ không bị tự đổi sang kiểu tên cũ như NameIdentifier.
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        services
            // Đăng ký JWT Bearer là cơ chế xác thực mặc định cho API.
            // Nghĩa là khi request có header Authorization: Bearer <token>,
            // ASP.NET sẽ dùng handler này để kiểm tra token.
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                // Authority là "gốc tin cậy" phát hành token.
                // Với Keycloak, nó thường có dạng:
                // http://host/realms/{realm}
                options.Authority = authOptions.Authority;

                // MetadataAddress là URL OpenID Connect metadata.
                // Tại đây ASP.NET sẽ đọc thông tin như issuer, signing keys...
                options.MetadataAddress = authOptions.MetadataAddress;

                // Dev local thường không dùng HTTPS cho Keycloak nên có thể cho phép false.
                // Production thì thường nên là true.
                options.RequireHttpsMetadata = authOptions.RequireHttpsMetadata;

                // Có kiểm tra audience hay không tùy cấu hình.
                // Nếu bật, token phải được cấp đúng cho client/resource mong muốn.
                options.TokenValidationParameters.ValidateAudience = authOptions.VerifyTokenAudience;
                options.TokenValidationParameters.ValidAudience = authOptions.Resource;

                // NameClaimType quyết định User.Identity.Name lấy từ claim nào.
                // Với Keycloak thì "preferred_username" là giá trị dễ dùng nhất.
                options.TokenValidationParameters.NameClaimType = PlatformAuthenticationConstants.PreferredUserNameClaim;

                // Nếu sau này map role vào token, ASP.NET sẽ hiểu role theo ClaimTypes.Role.
                options.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;

                // Keycloak thường đặt role trong JSON claim như realm_access/resource_access
                // thay vì phát thẳng claim role chuẩn của ASP.NET.
                // Ở đây ta convert các role đó sang ClaimTypes.Role để [Authorize(Roles = "...")] dùng được.
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = context =>
                    {
                        if (context.Principal is not null)
                            KeycloakRoleClaimsMapper.Map(context.Principal);
                        return Task.CompletedTask;
                    }
                };
            });

        // Bật authorization để [Authorize] hoạt động.
        services.AddAuthorization();

        return services;
    }

    public static WebApplication UsePlatformAuthentication(this WebApplication app)
    {
        // 1. Đọc token từ request và dựng HttpContext.User.
        app.UseAuthentication();

        // 2. Sau khi đã biết user là ai, mới kiểm tra [Authorize], policy, role...
        app.UseAuthorization();

        return app;
    }

    private static PlatformAuthenticationOptions GetPlatformAuthenticationOptions(this IConfiguration configuration)
    {
        // Tất cả key auth hiện đang nằm trong section "Keycloak".
        var keycloakSection = configuration.GetSection(PlatformAuthenticationConstants.KeycloakSectionName);

        return new PlatformAuthenticationOptions
        {
            // TrimEnd('/') để tránh bị double slash khi ghép URL bên trong options.
            AuthServerUrl = GetRequiredValue(keycloakSection, PlatformAuthenticationConstants.AuthServerUrlKey).TrimEnd('/'),
            Realm = GetRequiredValue(keycloakSection, PlatformAuthenticationConstants.RealmKey),
            Resource = GetRequiredValue(keycloakSection, PlatformAuthenticationConstants.ResourceKey),

            // Nếu config là "true" thì bật kiểm tra audience, còn thiếu/sai thì mặc định false.
            VerifyTokenAudience = bool.TryParse(keycloakSection[PlatformAuthenticationConstants.VerifyTokenAudienceKey], out var parsedVerifyAudience) && parsedVerifyAudience,

            // Nếu không cấu hình ssl-required thì fallback về "none" để dev local đỡ bị lỗi.
            SslRequired = keycloakSection[PlatformAuthenticationConstants.SslRequiredKey] ?? PlatformAuthenticationConstants.SslRequiredNone
        };
    }

    private static string GetRequiredValue(IConfiguration section, string key)
    {
        // Đây là helper để fail sớm và fail rõ ràng nếu thiếu config bắt buộc.
        // Như vậy app sẽ báo đúng key nào thiếu thay vì lỗi mơ hồ ở bước auth sau này.
        return section[key] ?? throw new InvalidOperationException($"{PlatformAuthenticationConstants.KeycloakSectionName}:{key} is not configured.");
    }
}
