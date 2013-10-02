using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography
{
    /// <summary>
    /// Configuration factory implementing best practices.
    /// </summary>
    public static class TemplateFactory
    {
        //public static SymmetricCipherConfiguration GetBlockCipherConfiguration(CipherTemplates template) {
            
        //}

        enum CipherTemplates
        {
            AES256_CTR,
            AES256_GCM,
            SOSEMANUK,
            HC256
        }
    }
}
