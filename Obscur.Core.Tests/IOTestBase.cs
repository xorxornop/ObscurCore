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

        public static readonly DirectoryInfo ProjectRoot = 
            new DirectoryInfo(Environment.CurrentDirectory).Parent.Parent;

        public readonly static DirectoryInfo TestDataSourceDirectory = 
            new DirectoryInfo(ProjectRoot.FullName + Path.DirectorySeparatorChar + "test-data-src");
        public static readonly DirectoryInfo SmallTextFilesSourceDirectory =
            new DirectoryInfo(TestDataSourceDirectory.FullName + Path.DirectorySeparatorChar + "small-text-files");
        public static readonly DirectoryInfo LargeBinaryFilesSourceDirectory =
            new DirectoryInfo(TestDataSourceDirectory.FullName + Path.DirectorySeparatorChar + "large-binary-files");

        public readonly static DirectoryInfo TestDataDestinationDirectory = 
            new DirectoryInfo(ProjectRoot.FullName + Path.DirectorySeparatorChar + "test-data-dst");
        public static readonly DirectoryInfo SmallTextFilesDestinationDirectory =
            new DirectoryInfo(TestDataDestinationDirectory.FullName + Path.DirectorySeparatorChar + "small-text-files");
        public static readonly DirectoryInfo LargeBinaryFilesDestinationDirectory =
            new DirectoryInfo(TestDataDestinationDirectory.FullName + Path.DirectorySeparatorChar + "large-binary-files");

        public static readonly DirectoryInfo PackageDestinationDirectory =
            new DirectoryInfo(TestDataDestinationDirectory.FullName + Path.DirectorySeparatorChar + "package-output");


        public static readonly string RawPayloadExtension = ".payload";
        public static readonly string PackageExtension = ".ocpkg";

        private const int RandomStreamLength = 1024 * 1024; // 1 MB
		protected static readonly MemoryStream RandomStream = new MemoryStream();
        protected static readonly MemoryStream SmallTextFile = new MemoryStream();
		protected static readonly MemoryStream LargeBinaryFile = new MemoryStream();

		public static readonly List<FileInfo> SmallTextFileList = new List<FileInfo>();
		public static readonly List<FileInfo> LargeBinaryFileList = new List<FileInfo>();


		static IOTestBase ()
		{
            foreach (var file in SmallTextFilesSourceDirectory.EnumerateFiles().Where(file 
                => !file.Extension.Equals(RawPayloadExtension)))
            {
				if (file.Name.EndsWith (".DS_Store"))
					continue;
			    SmallTextFileList.Add (file);
			}
			var fs = SmallTextFileList [0].OpenRead ();
			fs.CopyTo(SmallTextFile);
		    fs.Close();

			foreach (var file in LargeBinaryFilesSourceDirectory.EnumerateFiles().Where(file 
                => !file.Extension.Equals(RawPayloadExtension)))
            {
				if (file.Name.EndsWith (".DS_Store"))
					continue;
			    LargeBinaryFileList.Add (file);
			}
			fs = LargeBinaryFileList [0].OpenRead ();
			fs.CopyTo(LargeBinaryFile);
            fs.Close();
		}

        [SetUp]
        public void InitTest () {
			SmallTextFile.Seek (0, SeekOrigin.Begin);
			LargeBinaryFile.Seek (0, SeekOrigin.Begin);
            AuxPerTestInit();
        }

        public virtual void AuxPerTestInit () { } // Implement as required by overriding
    }
}
