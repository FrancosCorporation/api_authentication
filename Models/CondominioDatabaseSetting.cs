namespace apiOAuth.Models
{
    public class CondominioDatabaseSetting : ICondominioDatabaseSetting
    {
        public string ConnectionString {get; set;}
        public string DatabaseName {get; set;}
    }
    
    public interface ICondominioDatabaseSetting
    {
        string ConnectionString {get; set;}
        string DatabaseName {get; set;}
    }
}