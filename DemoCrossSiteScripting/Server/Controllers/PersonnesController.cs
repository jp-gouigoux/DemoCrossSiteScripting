using DemoCrossSiteScripting.Shared;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DemoCrossSiteScripting.Server.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PersonnesController : Controller
    {
        [HttpPost]
        public IActionResult CreationPersonne([FromBody] Personne personne)
        {
            try
            {
                using (var conn = new SqliteConnection("Data Source=test.db"))
                {
                    conn.Open();
                    var commande = conn.CreateCommand();
                    commande.CommandText = "INSERT INTO PERSONNES (nom, prenom, age) VALUES (@nom, @prenom, @age)";
                    commande.Parameters.Add(new SqliteParameter("nom", personne.Nom));
                    commande.Parameters.Add(new SqliteParameter("prenom", personne.Prenom));
                    commande.Parameters.Add(new SqliteParameter("age", personne.Age));
                    commande.ExecuteNonQuery();
                }
                return new CreatedResult("#", personne);
            }
            catch (Exception ex)
            {
                return new UnprocessableEntityObjectResult(ex.ToString());
            }
        }

        [HttpGet]
        public Tuple<List<Personne>, string> GetAll([FromQuery] string IndicationNom)
        {
            var donnees = new List<Personne>();
            string erreur = string.Empty;

            try
            {
                using (var conn = new SqliteConnection("Data Source=test.db"))
                {
                    conn.Open();
                    var commande = conn.CreateCommand();
                    commande.CommandText = "SELECT nom, prenom, age FROM PERSONNES WHERE nom LIKE @pattern";
                    commande.Parameters.AddWithValue("pattern", "%" + IndicationNom + "%");

                    using (var reader = commande.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            donnees.Add(
                                new Personne()
                                {
                                    Nom = reader.GetString(0),
                                    Prenom = reader.GetString(1),
                                    Age = reader.GetInt32(2)
                                });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                erreur = ex.ToString();
            }
            return new Tuple<List<Personne>, string>(donnees, erreur);
        }

        [HttpGet("fiche")]
        public ContentResult GenererFiche([FromQuery] string nom)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("<html>");
            sb.AppendLine("<body>");

            using (var conn = new SqliteConnection("Data Source=test.db"))
            {
                conn.Open();
                var commande = conn.CreateCommand();
                commande.CommandText = "SELECT prenom, age FROM PERSONNES WHERE nom=@nom";
                commande.Parameters.Add(new SqliteParameter("nom", nom));
                using (var reader = commande.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        sb.Append("<h1>").Append(reader.GetString(0)).Append(" ").Append(nom).AppendLine("</h1>"); // SECU (A03:2021-Injection) : faille de Cross Site Scripting rémanente dans la valeur de prénom, et qui peut donc impacter de nombreuses personnes si on envoie la valeur <img src="http://gouigoux.com/img/bouba.png" onload="alert('owned!')"/> dans la base de données avant d'afficher la fiche par http://localhost:62381/api/personnes/fiche?nom=Gouigoux (ou tout autre nom choisi)
                        sb.Append("<p>Agé.e de ").Append(reader.GetInt32(1).ToString()).AppendLine(" ans</p>");
                    }
                    else
                    {
                        // SECU (A03:2021-Injection) : faille de Cross Site Scripting non rémanente, c'est-à-dire qu'elle nécessite que quelqu'un lance l'URL "forgée", désormais intégrée dans la même catégorie que les injections SQL et autres attaques par évitement de la forme canonique ;
                        // si on passe sur le paramètre nom une valeur bien choisie comme http://localhost:62381/api/Personnes/fiche?nom=Lagaffe%3C/h1%3E%3Cimg%20src=%22http://gouigoux.com/img/bouba.png%22%20onload=%22alert(%27owned!%27)%22/%3E%3Ch1%3E, on injecte du JavaScript qui s'exécute
                        // ou bien plus pratique pour des attaques de type MITM, en utilisant quelque chose comme http://localhost:62381/api/Personnes/fiche?nom=Lagaffe%3C/h1%3E%3Cimg%20src=%22http://gouigoux.com/img/bouba.png%22%20onload=%22window.location=%27https://www.cybermalveillance.gouv.fr%27%22/%3E%3Ch1%3E et en maquillant le site initial
                        sb.Append("<h1>").Append(nom).Append(" ne fait pas partie de notre annuaire !").AppendLine("</h1>");
                    }
                }
            }

            sb.AppendLine("</body>");
            sb.AppendLine("</html>");
            return Content(sb.ToString(), "text/html", Encoding.UTF8);
        }
    }
}
