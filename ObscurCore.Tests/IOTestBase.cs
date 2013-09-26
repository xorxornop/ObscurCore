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
using System.IO;
using NUnit.Framework;

namespace ObscurCore.Tests
{
    public abstract class IOTestBase
    {
        public const int DefaultBufferSize = 4096;

        public virtual int GetBufferSize () { return DefaultBufferSize; }

        private const int RandomStreamLength = 1024 * 1024; // 1 MB

        private readonly static string _pathTestRoot = Directory.GetParent(Directory.GetParent(Environment.CurrentDirectory).FullName).FullName 
			+ Path.DirectorySeparatorChar + "test-data-src";

		protected static readonly MemoryStream RandomStream = new MemoryStream();

		public static readonly List<FileInfo> SmallTextFileList = new List<FileInfo>();
		public static readonly List<FileInfo> LargeBinaryFileList = new List<FileInfo>();

		protected static MemoryStream SmallTextFile = new MemoryStream();
		protected static MemoryStream LargeBinaryFile = new MemoryStream();

		static IOTestBase ()
		{
			var smallFiles = Directory.EnumerateFiles (_pathTestRoot + Path.DirectorySeparatorChar + "small-text-files");
			foreach (var file in smallFiles) {
				if (file.EndsWith (".payload"))
					continue;
				SmallTextFileList.Add (new FileInfo (file));
			}
			var fs = SmallTextFileList [0].OpenRead ();
			fs.CopyTo(SmallTextFile);

			var largeFiles = Directory.EnumerateFiles (_pathTestRoot + Path.DirectorySeparatorChar + "large-binary-files");
			foreach (var file in largeFiles) {
				if (file.EndsWith (".payload"))
					continue;
				LargeBinaryFileList.Add (new FileInfo (file));
			}
			fs = LargeBinaryFileList [0].OpenRead ();
			fs.CopyTo(LargeBinaryFile);

			var rng = new Random();
			var data = new byte[2048];
			while (RandomStream.Length < RandomStreamLength) {
				rng.NextBytes(data);
				RandomStream.Write(data, 0, data.Length);
			}
		}

        [SetUp]
        public void InitTest () {
			SmallTextFile.Seek (0, SeekOrigin.Begin);
			LargeBinaryFile.Seek (0, SeekOrigin.Begin);
			RandomStream.Seek (0, SeekOrigin.Begin);
            AuxPerTestInit();
        }

        public virtual void AuxPerTestInit () { } // Implement as required by overriding
    }
}
