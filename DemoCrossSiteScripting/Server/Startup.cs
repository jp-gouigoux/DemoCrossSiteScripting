using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Linq;

namespace DemoCrossSiteScripting.Server
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddControllersWithViews();
            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            using (var conn = new SqliteConnection("Data Source=test.db"))
            {
                conn.Open();
                var commande = conn.CreateCommand();
                commande.CommandText = "DROP TABLE IF EXISTS PERSONNES; CREATE TABLE PERSONNES (nom VARCHAR(32), prenom VARCHAR(32), age INT)";
                commande.ExecuteNonQuery();

                commande = conn.CreateCommand();
                commande.CommandText = "DROP TABLE IF EXISTS CONTRATS; CREATE TABLE CONTRATS (entreprise VARCHAR(32), sujet VARCHAR(32), montant INT)";
                commande.ExecuteNonQuery();

                commande = conn.CreateCommand();
                commande.CommandText = "DROP TABLE IF EXISTS USERS; CREATE TABLE USERS (login VARCHAR(32), hash VARCHAR(32))";
                commande.ExecuteNonQuery();

                commande = conn.CreateCommand();
                commande.CommandText = "INSERT INTO PERSONNES (nom, prenom, age) VALUES ('Lagaffe', 'Gaston', 63)";
                commande.ExecuteNonQuery();

                commande = conn.CreateCommand();
                commande.CommandText = "INSERT INTO CONTRATS (entreprise, sujet, montant) VALUES ('Minist?re', 'Contrat ultra-secret', 1000000)";
                commande.ExecuteNonQuery();
            }

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseWebAssemblyDebugging();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            app.UseBlazorFrameworkFiles();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
                endpoints.MapControllers();
                endpoints.MapFallbackToFile("index.html");
            });
        }
    }
}
