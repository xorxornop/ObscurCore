using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ObscurCore.Cryptography;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Packaging
{
    class Utilities
    {
        public static List<PayloadItem> GetItemsStreamExample(List<FileInfo> files) {
			var items = new List<PayloadItem> ();

            foreach (var fileInfo in files) {
                var t = fileInfo;
                var payloadItem = new PayloadItem()
                    {
                        RelativePath = t.Name,
                        ExternalLength = t.Length,
                        Type = PayloadItemTypes.Binary,
                        //Compression = new CompressionConfiguration () { AlgorithmName = CompressionAlgorithms.LZ4.ToString() },
                        //Encryption = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration(SymmetricBlockCiphers.AES, BlockCipherModes.CTR, BlockCipherPaddings.None),
                        Encryption = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.SOSEMANUK)
                    };

                payloadItem.Encryption.Key = new byte[payloadItem.Encryption.KeySize / 8];
                StratCom.EntropySource.NextBytes(payloadItem.Encryption.Key);
                payloadItem.SetStreamBinding(fileInfo.OpenRead);

                items.Add(payloadItem);
            }

            return items;
		}

        public static List<PayloadItem> GetItemsBlockExample(List<FileInfo> files) {
			var items = new List<PayloadItem> ();

            foreach (var fileInfo in files) {
                var t = fileInfo;
                var payloadItem = new PayloadItem()
                    {
                        RelativePath = t.Name,
                        ExternalLength = t.Length,
                        Type = PayloadItemTypes.Binary,
                        //Compression = new CompressionConfiguration () { AlgorithmName = CompressionAlgorithms.LZ4.ToString() },
                        Encryption = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration(SymmetricBlockCiphers.Serpent, 
                            BlockCipherModes.CTR, BlockCipherPaddings.None)
                    };

                payloadItem.Encryption.Key = new byte[payloadItem.Encryption.KeySize / 8];
                StratCom.EntropySource.NextBytes(payloadItem.Encryption.Key);
                payloadItem.SetStreamBinding(fileInfo.OpenRead);

                items.Add(payloadItem);
            }

            return items;
		}
    }
}
