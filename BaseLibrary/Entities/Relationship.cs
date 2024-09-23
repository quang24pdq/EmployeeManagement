
using System.Text.Json.Serialization;


namespace BaseLibrary.Entities
{
    public class Relationship
    {
        [JsonIgnore]
        public List<Employee>? employees { get; set; }
    }
}
