using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LJ.Identidade.API.Models
{
    public class UsuarioRespostaLogin
    {
        public string AccessToken { get; set; }
        public double ExpiresIn { get; set; }
        public UsuarioToken UsuarioToken { get; set; }
    }
}
