using Algorand;
using Algorand.Algod;
using Algorand.KMD;
using Fido2NetLib;

namespace AlgorandAuth
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddRazorPages();

            
            

            // Use the in-memory implementation of IDistributedCache.
            builder.Services.AddMemoryCache();
            builder.Services.AddDistributedMemoryCache();

            builder.Services.AddSession(options =>
            {
                // Set a short timeout for easy testing.
                options.IdleTimeout = TimeSpan.FromMinutes(2);
                options.Cookie.HttpOnly = true;
                // Strict SameSite mode is required because the default mode used
                // by ASP.NET Core 3 isn't understood by the Conformance Tool
                // and breaks conformance testing
                options.Cookie.SameSite = SameSiteMode.Unspecified;
            });


            builder.Configuration
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddEnvironmentVariables();




            // Use the configuration
            var configuration = builder.Configuration;

            builder.Services.AddFido2(options =>
            {
                options.ServerDomain = configuration["fido2:serverDomain"];
                options.ServerName = "FIDO2 Test";
                options.Origins = configuration.GetSection("fido2:origins").Get<HashSet<string>>();
                options.TimestampDriftTolerance = configuration.GetValue<int>("fido2:timestampDriftTolerance");
                options.MDSCacheDirPath = configuration["fido2:MDSCacheDirPath"];
            })
            .AddCachedMetadataService(config =>
            {
                config.AddFidoMetadataRepository(httpClientBuilder =>
                {
                    //TODO: any specific config you want for accessing the MDS
                });
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseSession();
            app.UseRouting();

            app.UseAuthorization();

            app.MapRazorPages();

            app.Run();
        }
    }
}
