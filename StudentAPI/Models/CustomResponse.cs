using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace StudentAPI.Models
{
    public class CustomResponse
    {
        public string Token { get; set; }
        public DateTime expiration { get; set; }
    }
}
