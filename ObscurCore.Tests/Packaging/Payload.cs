//
//  Copyright 2013  Matthew Ducker
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using NUnit.Framework;
using ObscurCore.Cryptography;
using ObscurCore.DTO;
using ObscurCore.Extensions.DTO;
using ObscurCore.Extensions.Enumerations;
using ObscurCore.Packaging;

namespace ObscurCore.Tests.Packaging
{
	public class Payload
	{
	    private const string DemuxDir = "demuxed";

        private readonly static List<FileInfo> Files = IOTestBase.SmallTextFileList;

		public Payload ()
		{
		}

		[TestFixtureSetUp]
		public void InitFixture () {

		}

		[Test]
		public void Simple () {
			var items = GetItems (Files.Count);
			var payloadConfig = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutSchemes.Simple);
			DoMux (payloadConfig, items, Files, true);
		}

		[Test]
		public void Frameshift () {
			var items = GetItems (Files.Count);
			var payloadConfig = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutSchemes.Frameshift);
			DoMux (payloadConfig, items, Files, true);
		}

#if(INCLUDE_FABRIC)
        [Test]
		public void Fabric () {
			var items = GetItems (_Files.Count);
            //var payloadConfig = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutSchemes.Fabric);

		    var payloadConfig = new PayloadLayoutConfiguration()
		        {
		            SchemeName = PayloadLayoutSchemes.Fabric.ToString(),
                    SchemeConfiguration = FabricConfigurationUtility.WriteFixedStriping(FabricMux.DefaultFixedStripeLength),
		            //SchemeConfiguration = FabricConfigurationUtility.WriteVariableStriping(FabricMux.MinimumStripeLength, FabricMux.MaximumStripeLength),
		            StreamPRNGName = "Salsa20",
		            StreamPRNGConfiguration = Salsa20GeneratorConfigurationUtility.WriteRandom(),
		            SecondaryPRNGName = "Salsa20",
		            SecondaryPRNGConfiguration = Salsa20GeneratorConfigurationUtility.WriteRandom()
		        };

			DoMux (payloadConfig, items, _Files);
		}
#endif

		protected List<PayloadItem> GetItems(int howMany) {
			var items = new List<PayloadItem> ();
            var sRng = StratCom.EntropySource;

		    for (var i = 0; i < howMany; i++) {
		        var payloadItem = new PayloadItem () {
                    RelativePath = Files[i].Name,
				    Type = PayloadItemTypes.Binary,
				    //Compression = new CompressionConfiguration () { AlgorithmName = CompressionAlgorithms.LZ4.ToString() },
				    //Encryption = new BlockCipherConfiguration(SymmetricBlockCiphers.AES, BlockCipherModes.CTR, BlockCipherPaddingTypes.None),
                    Encryption = new StreamCipherConfiguration(SymmetricStreamCiphers.SOSEMANUK)
			    };
                payloadItem.Encryption.Key = new byte[payloadItem.Encryption.KeySize / 8];
			    sRng.NextBytes(payloadItem.Encryption.Key);
			    
			    items.Add (payloadItem);
		    }

			return items;
		}

		protected List<Func<Stream, DecoratingStream>> GetTransforms(List<PayloadItem> items, bool writingPayload) {
            return items.Select(item => (Func<Stream, DecoratingStream>) (binding => item.BindTransformStream(writingPayload, binding))).ToList();
		}

	    protected void DoMux(PayloadLayoutConfiguration payloadConfig, List<PayloadItem> items, List<FileInfo> files,  bool outputPayload = false) {
			
            var ms = new MemoryStream ();

	        for (var index = 0; index < items.Count; index++) {
	            var index1 = index;
	            items[index].SetStreamBinding(() => new FileStream(files[index1].FullName, FileMode.Open));
	            items[index].ExternalLength = items[index].StreamBinding.Length;
	        }

	        var transforms = GetTransforms(items, true);
			var mux = Source.CreatePayloadMultiplexer(payloadConfig.SchemeName.ToEnum<PayloadLayoutSchemes>(), true, ms, 
                items.ToList<IStreamBinding>(), transforms, payloadConfig);
			
			Assert.DoesNotThrow (mux.ExecuteAll);

            // Get internal lengths
	        for (var i = 0; i < items.Count; i++) {
	            items[i].InternalLength = mux.GetItemIO(i);
	        }

            var muxIn = mux.TotalSourceIO;

			foreach (var item in items) {
				item.StreamBinding.Close();
			}

            // Write out muxed payload - optional
	        if (outputPayload) {

			    var path = Files [0].Directory.FullName + 
				    Path.DirectorySeparatorChar + payloadConfig.SchemeName.ToLower () + IOTestBase.PayloadExtension;
				using (var fs = new FileStream(path, FileMode.Create)) {
                    ms.WriteTo(fs);
                }
	        }

            // DEMUX

            var demuxPath = files[0].Directory.FullName + Path.DirectorySeparatorChar + DemuxDir;
	        foreach (var payloadItem in items) {
	            if (!Directory.Exists (DemuxDir)) Directory.CreateDirectory (demuxPath);
	            PayloadItem item = payloadItem;
	            payloadItem.SetStreamBinding(() => new FileStream(demuxPath + Path.DirectorySeparatorChar + item.RelativePath, FileMode.Create));
	        }

	        transforms = GetTransforms(items, false);

	        ms.Seek(0, SeekOrigin.Begin);
            mux = Source.CreatePayloadMultiplexer(payloadConfig.SchemeName.ToEnum<PayloadLayoutSchemes>(), false, ms, 
                items.ToList<IStreamBinding>(), transforms, payloadConfig);

            Assert.DoesNotThrow(mux.ExecuteAll);

	        var muxOut = mux.TotalDestinationIO;

            foreach (var item in items) {
                item.StreamBinding.Close();
            }

            if (mux is FrameshiftMux) {
                Assert.Pass("MuxOut: {0}, Overhead: {1:P4} ({2} bytes) ; MuxIn: {3}",
                    muxOut, ((double) mux.Overhead/(double) muxOut), mux.Overhead, muxIn);
            } else {
                Assert.Pass("MuxOut: {0}, MuxIn: {1}", muxOut, muxIn);
            }
	    }

	}
}

