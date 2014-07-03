using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ObscurCore.Cryptography.Authentication;
using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Block;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.DTO;

namespace ObscurCore.Tests.Packaging
{
    class Utilities
    {
        public static List<PayloadItem> GetItemsStreamExample(List<FileInfo> files) {
			var items = new List<PayloadItem> ();

            foreach (var fileInfo in files) {
                var t = fileInfo;
				int authOutputSize;
				var payloadItem = new PayloadItem {
                    RelativePath = t.Name,
                    ExternalLength = t.Length,
                    Type = PayloadItemType.File,
					SymmetricCipher = CipherConfigurationFactory.CreateStreamCipherConfiguration(StreamCipher.Sosemanuk),
					Authentication = AuthenticationConfigurationFactory.CreateAuthenticationConfiguration(MacFunction.Blake2B256, out authOutputSize)
                };

				payloadItem.SymmetricCipherKey = new byte[payloadItem.SymmetricCipher.KeySizeBits / 8];
				StratCom.EntropySupplier.NextBytes(payloadItem.SymmetricCipherKey);
				payloadItem.AuthenticationKey = new byte[payloadItem.Authentication.KeySizeBits.Value / 8];
				StratCom.EntropySupplier.NextBytes(payloadItem.AuthenticationKey);

                payloadItem.SetStreamBinding(fileInfo.OpenRead);

                items.Add(payloadItem);
            }

            return items;
		}

        public static List<PayloadItem> GetItemsBlockExample(List<FileInfo> files) {
			var items = new List<PayloadItem> ();

            foreach (var fileInfo in files) {
                var t = fileInfo;
				int authOutputSize;
				var payloadItem = new PayloadItem {
                    RelativePath = t.Name,
                    ExternalLength = t.Length,
                    Type = PayloadItemType.File,
                    SymmetricCipher = CipherConfigurationFactory.CreateBlockCipherConfiguration(BlockCipher.Serpent, 
						BlockCipherMode.Ctr, BlockCipherPadding.None),
					Authentication = AuthenticationConfigurationFactory.CreateAuthenticationConfiguration(MacFunction.Blake2B256, out authOutputSize)
                };

                payloadItem.SymmetricCipherKey = new byte[payloadItem.SymmetricCipher.KeySizeBits / 8];
                StratCom.EntropySupplier.NextBytes(payloadItem.SymmetricCipherKey);
				payloadItem.AuthenticationKey = new byte[payloadItem.Authentication.KeySizeBits.Value / 8];
				StratCom.EntropySupplier.NextBytes(payloadItem.AuthenticationKey);

                payloadItem.SetStreamBinding(fileInfo.OpenRead);

                items.Add(payloadItem);
            }

            return items;
		}
    }
}
