using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Platform.Api.Extensions;

public static class CorsExtensions
{
    private const string CorsSectionName = "Cors";
    private const string AllowedOriginsKey = "AllowedOrigins";
    private const string PlatformDefaultPolicy = "PlatformDefaultPolicy";

    public static IServiceCollection AddPlatformCors(this IServiceCollection services, IConfiguration configuration)
    {
        // Đọc danh sách Origins từ section "Cors:AllowedOrigins" trong appsettings.json
        var allowedOrigins = configuration.GetSection($"{CorsSectionName}:{AllowedOriginsKey}").Get<string[]>();

        // Nếu không có cấu hình, mặc định cho phép localhost:3000 để việc dev không bị gián đoạn
        if (allowedOrigins == null || allowedOrigins.Length == 0)
        {
            allowedOrigins = new[] { "http://localhost:3000" };
        }

        services.AddCors(options =>
        {
            options.AddPolicy(PlatformDefaultPolicy, policy =>
            {
                policy.WithOrigins(allowedOrigins)
                      .AllowAnyHeader()
                      .AllowAnyMethod()
                      .AllowCredentials();
            });
        });

        return services;
    }

    public static IApplicationBuilder UsePlatformCors(this IApplicationBuilder app)
    {
        return app.UseCors(PlatformDefaultPolicy);
    }
}
