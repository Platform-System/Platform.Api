using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Platform.Api.Extensions;

public static class MigrationExtensions
{
    public static async Task ApplyMigrationsAsync<TContext>(this IApplicationBuilder app) where TContext : DbContext
    {
        using var scope = app.ApplicationServices.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<TContext>();
        await context.Database.MigrateAsync();
    }
}
