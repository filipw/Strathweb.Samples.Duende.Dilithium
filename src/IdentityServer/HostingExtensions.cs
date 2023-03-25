using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Services;
using Serilog;

namespace IdentityServer;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<DilithiumCredentials>();
        builder.Services.AddTransient<ITokenCreationService, DilithiumCompatibleTokenCreationService>();
        builder.Services.AddTransient<IDiscoveryResponseGenerator, DilithiumAwareDiscoveryResponseGenerator>();

        builder.Services.AddIdentityServer(options =>
            {
                options.EmitStaticAudienceClaim = true;
            })
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryApiResources(Config.ApiResources)
            .AddInMemoryClients(Config.Clients);

        return builder.Build();
    }
    
    public static WebApplication ConfigurePipeline(this WebApplication app)
    { 
        app.UseSerilogRequestLogging();
    
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseIdentityServer();
        return app;
    }
}
