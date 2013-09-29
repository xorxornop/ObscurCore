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
using System.Linq;
using NUnit.Framework;

namespace ObscurCore.Tests
{
    public abstract class IOTestBase
    {
        public const int DefaultBufferSize = 4096;

        public virtual int GetBufferSize () { return DefaultBufferSize; }

        private const int RandomStreamLength = 1024 * 1024; // 1 MB

        public readonly static DirectoryInfo TestDataDirectory = new DirectoryInfo(Directory.GetParent(Directory.GetParent(Environment.CurrentDirectory)
            .FullName).FullName + Path.DirectorySeparatorChar + "test-data-src");

        public static readonly DirectoryInfo SmallTextFilesDirectory =
            new DirectoryInfo(TestDataDirectory.FullName + Path.DirectorySeparatorChar + "small-text-files");

        public static readonly DirectoryInfo LargeBinaryFilesDirectory =
            new DirectoryInfo(TestDataDirectory.FullName + Path.DirectorySeparatorChar + "large-binary-files");

        public static readonly string PayloadExtension = ".payload";

		protected static readonly MemoryStream RandomStream = new MemoryStream();
        protected static readonly MemoryStream SmallTextFile = new MemoryStream();
		protected static readonly MemoryStream LargeBinaryFile = new MemoryStream();

		public static readonly List<FileInfo> SmallTextFileList = new List<FileInfo>();
		public static readonly List<FileInfo> LargeBinaryFileList = new List<FileInfo>();


		static IOTestBase ()
		{
            foreach (var file in SmallTextFilesDirectory.EnumerateFiles().Where(file 
                => !file.Extension.Equals(PayloadExtension)))
            {
			    SmallTextFileList.Add (file);
			}
			var fs = SmallTextFileList [0].OpenRead ();
			fs.CopyTo(SmallTextFile);

			foreach (var file in LargeBinaryFilesDirectory.EnumerateFiles().Where(file 
                => !file.Extension.Equals(PayloadExtension)))
            {
			    LargeBinaryFileList.Add (file);
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
