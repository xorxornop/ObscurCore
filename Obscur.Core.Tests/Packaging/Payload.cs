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
using System.Diagnostics;
using System.IO;
using NUnit.Framework;
using Obscur.Core.DTO;
using Obscur.Core.Packaging.Multiplexing;
using Obscur.Core.Packaging.Multiplexing.Primitives;

namespace Obscur.Core.Tests.Packaging
{
	public class Payload
	{
	    private const string DemuxDir = "demuxed";

        //private readonly static List<FileInfo> SourceFiles = IOTestBase.SmallTextFileList;
	    //private static readonly DirectoryInfo DestinationDirectory = IOTestBase.SmallTextFilesDestinationDirectory;

        private readonly static List<FileInfo> SourceFiles = IOTestBase.LargeBinaryFileList;
	    private static readonly DirectoryInfo DestinationDirectory = IOTestBase.LargeBinaryFilesDestinationDirectory;

		[TestFixtureSetUp]
		public void InitFixture () {

		}

		[Test]
		public void Simple () {
			var items = Utilities.GetItemsStreamExample(SourceFiles);
			var payloadConfig = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutScheme.Simple);
			DoMux (payloadConfig, items, SourceFiles, true);
		}

		[Test]
		public void Frameshift () {
			var items = Utilities.GetItemsBlockExample(SourceFiles);
			var payloadConfig = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutScheme.Frameshift);
			DoMux (payloadConfig, items, SourceFiles, true);
		}

#if INCLUDE_FABRIC
        [Test]
		public void Fabric () {
			var items = Utilities.GetItemsStreamExample(SourceFiles);
            var payloadConfig = PayloadLayoutConfigurationFactory.CreateDefault(PayloadLayoutScheme.Fabric);
			DoMux (payloadConfig, items, SourceFiles);
		}
#endif

	    protected void DoMux(PayloadConfiguration payloadConfig, List<PayloadItem> items, List<FileInfo> files,  bool outputPayload = false) {
			
            var ms = new MemoryStream ();

	        for (var index = 0; index < items.Count; index++) {
	            var index1 = index;
	            items[index].SetStreamBinding(() => new FileStream(files[index1].FullName, FileMode.Open));
	            items[index].ExternalLength = items[index].StreamBinding.Length;
	        }

			var itemPreKeys = new Dictionary<Guid, byte[]> ();

			var mux = PayloadMuxFactory.CreatePayloadMultiplexer(payloadConfig.SchemeName.ToEnum<PayloadLayoutScheme>(), true, ms, 
				items, itemPreKeys, payloadConfig);
			
			Assert.DoesNotThrow (mux.Execute);

            Debug.Print("\n##### END OF MUXING OPERATION #####\n");

			foreach (var item in items) {
				item.StreamBinding.Close();
			}

            // Write out muxed payload - optional
	        if (outputPayload) {
				if (!DestinationDirectory.Exists)
					DestinationDirectory.Create ();
			    var path = DestinationDirectory.FullName + Path.DirectorySeparatorChar + 
                    payloadConfig.SchemeName.ToLower () + IOTestBase.RawPayloadExtension;
				using (var fs = new FileStream(path, FileMode.Create)) {
                    ms.WriteTo(fs);
                }
	        }

            // DEMUX

            var demuxPath = DestinationDirectory.FullName + Path.DirectorySeparatorChar + DemuxDir;
			if (!Directory.Exists (demuxPath)) Directory.CreateDirectory (demuxPath);
	        foreach (var payloadItem in items) {
	            PayloadItem item = payloadItem;
	            payloadItem.SetStreamBinding(() => new FileStream(demuxPath + Path.DirectorySeparatorChar + item.Path, FileMode.Create));
	        }

	        ms.Seek(0, SeekOrigin.Begin);
			mux = PayloadMuxFactory.CreatePayloadMultiplexer(payloadConfig.SchemeName.ToEnum<PayloadLayoutScheme>(), false, ms, 
				items, itemPreKeys, payloadConfig);

            Assert.DoesNotThrow(mux.Execute);

            Debug.Print("\n##### END OF DEMUXING OPERATION #####\n");

            foreach (var item in items) {
                item.StreamBinding.Close();
            }

            if (mux is FrameshiftPayloadMux) {
				Assert.Pass("Overhead: {0} bytes", ((FrameshiftPayloadMux)mux).Overhead);
            } else {
                Assert.Pass();
            }
	    }

	}
}

