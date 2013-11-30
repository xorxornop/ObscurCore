using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ObscurCore.Cryptography;
using ObscurCore.DTO;
using ObscurCore.Extensions.ByteArrays;
using ObscurCore.Extensions.DTO;
using ObscurCore.Extensions.Streams;
using ObscurCore.Packaging;
using ProtoBuf;

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


        private SymmetricCipherConfiguration _manifestCipherConfig;

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
        /// Read a package from a stream.
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

        /// <summary>
        /// Write package out to bound stream.
        /// </summary>
        public void Write() {

            Debug.Print(DebugUtility.CreateReportString("Package", "Write", "[*PACKAGE START*] Header offset (absolute)",
                _stream.Position.ToString()));

            // Write the header tag
            var headerTag = Athena.Packaging.GetHeaderTag();
            _stream.Write(headerTag, 0, headerTag.Length);

            Debug.Print(DebugUtility.CreateReportString("Package", "Write", "Manifest header offset (absolute)",
                _stream.Position.ToString()));

            // Serialise and write ManifestHeader (this part is written as plaintext, otherwise INCEPTION!)
            StratCom.Serialiser.SerializeWithLengthPrefix(_stream, _manifestHeader, typeof (ManifestHeader),
                PrefixStyle.Base128, 0);

            /* Prepare for writing payload */

            // Check all payload items have associated key data for their encryption, supplied either in item Key field or 'payloadKeys' param.
            if (_manifest.PayloadItems.Any(item => item.Encryption.Key == null || item.Encryption.Key.Length == 0)) {
                //throw new ItemKeyMissingException(item);
                throw new Exception("At least one item is missing a key.");
            }

            // Create and bind transform functions (compression, encryption, etc) defined by items' configurations to those items
            var transformFunctions = _manifest.PayloadItems.Select(item => (Func<Stream, DecoratingStream>) (binding =>
                item.BindTransformStream(true, binding))).ToList();

            /* Write the payload to temporary storage (payloadTemp) */
            PayloadLayoutSchemes payloadScheme;
            try {
                payloadScheme = _manifest.PayloadConfiguration.SchemeName.ToEnum<PayloadLayoutSchemes>();
            } catch (Exception) {
                throw new PackageConfigurationException(
                    "Package payload schema specified is unsupported/unknown or missing.");
            }
            // Bind the multiplexer to the temp stream
            var mux = Source.CreatePayloadMultiplexer(payloadScheme, true, _tempStream,
                _manifest.PayloadItems.ToList<IStreamBinding>(),
                transformFunctions, _manifest.PayloadConfiguration);

            mux.ExecuteAll();

            // Get internal lengths of the written items from the muxer and commit them to the manifest
	        for (var i = 0; i < _manifest.PayloadItems.Count; i++) {
	            _manifest.PayloadItems[i].InternalLength = mux.GetItemIO(i, source: false);
	        }

            Debug.Print(DebugUtility.CreateReportString("Package", "Write", "Manifest working key",
                _manifestCipherConfig.Key.ToHexString()));

            using (var manifestTemp = new MemoryStream()) {
                /* Write the manifest in encrypted form */
                using (var cs = new SymmetricCryptoStream(manifestTemp, true, _manifestCipherConfig, null, false)) {
                    var manifestMS = StratCom.SerialiseDTO(_manifest);
                    manifestMS.WriteTo(cs);
                    manifestMS.Close();
                }
                Debug.Print(DebugUtility.CreateReportString("Package", "Write", "Manifest length prefix offset (absolute)",
                    _stream.Position.ToString()));
                _stream.WritePrimitive((UInt32)manifestTemp.Length); // Manifest length is written as uint32
                Debug.Print(DebugUtility.CreateReportString("Package", "Write", "Manifest offset (absolute)",
                    _stream.Position.ToString()));

                manifestTemp.WriteTo(_stream);
            }

            // Clear manifest key from memory
            Array.Clear(_manifestCipherConfig.Key, 0, _manifestCipherConfig.Key.Length);

            // Write payload offset filler, where applicable
            if (_manifest.PayloadConfiguration.Offset > 0) {
                var paddingBytes = new byte[_manifest.PayloadConfiguration.Offset];
                StratCom.EntropySource.NextBytes(paddingBytes);
                _stream.Write(paddingBytes, 0, paddingBytes.Length);
            }

            Debug.Print(DebugUtility.CreateReportString("Package", "Write", "Payload offset (absolute)",
                    _stream.Position.ToString()));

            /* Write out payloadTemp to real destination */
            _tempStream.Seek(0, SeekOrigin.Begin);
            _tempStream.CopyTo(_stream);

            Debug.Print(DebugUtility.CreateReportString("Package", "Write", "Trailer offset (absolute)",
                    _stream.Position.ToString()));

            // Write the trailer tag
            var trailerTag = Athena.Packaging.GetTrailerTag();
            _stream.Write(trailerTag, 0, trailerTag.Length);

            Debug.Print(DebugUtility.CreateReportString("Package", "Write", "[* PACKAGE END *] Offset (absolute)",
                    _stream.Position.ToString()));

            // All done! HAPPY DAYS.
            //destination.Close();
        }

        

        public void ReadOutTo() {
            
        }
    }
}
