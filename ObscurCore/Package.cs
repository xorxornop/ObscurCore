using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ObscurCore.Cryptography;
using ObscurCore.DTO;

namespace ObscurCore
{
    /// <summary>
    /// Virtual object that provides read-write capabilities for packages.
    /// </summary>
    public sealed class Package
    {
        /// <summary>
        /// Stream where package is being written to or read from.
        /// </summary>
        private Stream _stream;

        /// <summary>
        /// Stream bound to memory or disk serving as storage for the payload during a write. 
        /// Uses memory by default. Larger writes should use disk-backed streams.
        /// </summary>
        private Stream _tempStream;


        private int _startStreamOffset, _payloadStreamOffset;

        private Manifest _manifest;
        private ManifestHeader _manifestHeader;

        internal ManifestHeader ManifestHeader {
            get { return _manifestHeader; }
            set { _manifestHeader = value; }
        }

        internal Manifest Manifest {
            get { return _manifest; }
            set { _manifest = value; }
        }

        


        /// <summary>
        /// Add a file-type payload item to the package with a relative path of root (/) in the manifest. 
        /// Default encryption is used.
        /// </summary>
        /// <remarks>Default encryption is AES-256/CTR with random key and IV.</remarks>
        /// <param name="filePath">Path of the file to add.</param>
        public void AddFile(string filePath) {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Exists) {
                throw new FileNotFoundException();
            }

            var newItem = new PayloadItem
                    {
                        ExternalLength = fileInfo.Length,
                        Type = PayloadItemTypes.Utf8,
                        RelativePath = String.IsNullOrEmpty(fileInfo.Extension) ? fileInfo.Name 
                            : String.Format("{0}.{1}", fileInfo.Name, fileInfo.Extension),
                        Encryption = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration
                            (SymmetricBlockCipher.Aes, BlockCipherMode.Ctr, BlockCipherPadding.None)
                    };
            newItem.SetStreamBinding(() => File.OpenRead(filePath));
            _manifest.PayloadItems.Add(newItem);
        }

        /// <summary>
        /// Add a text payload item (encoded in UTF-8) to the package with a relative path 
        /// of root (/) in the manifest. Default encryption is used.
        /// </summary>
        /// <remarks>Default encryption is AES-256/CTR with random key and IV.</remarks>
        /// <param name="name">Name of the item. Subject of the text is suggested.</param>
        /// <param name="text">Content of the item.</param>
        public void AddText(string name, string text) {
            var stream = new MemoryStream(Encoding.UTF8.GetBytes(text));
            var newItem = new PayloadItem
                    {
                        ExternalLength = stream.Length,
                        Type = PayloadItemTypes.Utf8,
                        RelativePath = name,
                        Encryption = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration
                            (SymmetricBlockCipher.Aes, BlockCipherMode.Ctr, BlockCipherPadding.None)
                    };
            newItem.SetStreamBinding(() => stream);
            _manifest.PayloadItems.Add(newItem);
        }

        /// <summary>
        /// Add a directory of files as payload items to the package with a relative path 
        /// of root (/) in the manifest. Default encryption is used.
        /// </summary>
        /// <remarks>Default encryption is AES-256/CTR with random key and IV.</remarks>
        /// <param name="path">Path of the directory to search for and add files from.</param>
        /// <param name="search">Search for files in subdirectories (default) or not.</param>
        public void AddDirectory(string path, SearchOption search = SearchOption.AllDirectories) {
            var dir = new DirectoryInfo(path);
            var rootPathLength = dir.FullName.Length;
            var files = dir.EnumerateFiles("*", search);

            foreach (var file in files) {
                var newItem = new PayloadItem
                    {
                        ExternalLength = file.Length,
                        Type = PayloadItemTypes.Binary,
                        RelativePath = search == SearchOption.AllDirectories
                                ? file.FullName.Remove(0, rootPathLength + 1)
                                : file.Name,
                        Encryption = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration
                            (SymmetricBlockCipher.Aes, BlockCipherMode.Ctr, BlockCipherPadding.None)
                    };
                var filePath = file.FullName; // provide consistent behaviour i.r.t. closure variable
                newItem.SetStreamBinding(() => File.OpenRead(filePath));
                if (Path.DirectorySeparatorChar != Athena.Packaging.PathDirectorySeperator) {
                    newItem.RelativePath = newItem.RelativePath.Replace(Path.DirectorySeparatorChar, Athena.Packaging.PathDirectorySeperator);
                }

                _manifest.PayloadItems.Add(newItem);
            }
        }







        /// <summary>
        /// Read a package from a file.
        /// </summary>
        /// <returns></returns>
        //public static Package FromFile(string filePath) {
            
        //}

        /// <summary>
        /// Read a package from a file.
        /// </summary>
        /// <returns></returns>
        //public static Package FromStream() {
            
        //}

        /// <summary>
        /// Create a new package for writing using symmetric-only encryption for security.
        /// </summary>
        public Package(byte[] key) {
            
        }

        /// <summary>
        /// Constructor that does nothing. Used for static-origin inits (reading).
        /// </summary>
        internal Package() {
            
        }


        public void Write() {
            
        }

        public void ReadOutTo() {
            
        }
    }
}
