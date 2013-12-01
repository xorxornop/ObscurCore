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

		public int FormatVersion
		{
			get { return _manifestHeader.FormatVersion; }
			set { throw new NotImplementedException (); }
		}

        
		/// <summary>
		/// Add a text payload item (encoded in UTF-8) to the package with a relative path 
		/// of root (/) in the manifest. Default encryption is used.
		/// </summary>
		/// <param name="name">Name of the item. Subject of the text is suggested.</param>
		/// <param name="text">Content of the item.</param>
		public void AddText(string name, string text) {
			if(String.IsNullOrEmpty(name) || String.IsNullOrWhiteSpace) {
				throw new ArgumentException ();
			}
			var stream = new MemoryStream(Encoding.UTF8.GetBytes(text));
			var newItem = CreateItem (stream, PayloadItemTypes.Utf8, stream.Length, name, false);

			_manifest.PayloadItems.Add(newItem);
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
			var itemStream = File.OpenRead (filePath);
			var newItem = CreateItem (itemStream, PayloadItemTypes.Binary, fileInfo.Length, fileInfo.Name, false);

            _manifest.PayloadItems.Add(newItem);
        }

		/// <summary>
		/// Creates a new PayloadItem DTO object, but does not add it to the manifest, returning it instead.
		/// </summary>
		/// <returns>A payload item.</returns>
		/// <remarks>Default encryption is AES-256/CTR with random IV and key.</remarks>
		/// <param name="itemData">Item data.</param>
		/// <param name="itemType">Type of the item, e.g., Utf8 (text) or Binary (data/file).</param>
		/// <param name="extLength">External length (outside the payload) of the item.</param>
		/// <param name="relPath">Relative path of the item.</param>
		/// <param name="skipCrypto">If set to <c>true</c>, leaves Encryption property set to null - for post-method-modification.</param>
		private PayloadItem CreateItem(Stream itemData, PayloadItemTypes itemType, long extLength, string relPath, bool skipCrypto = false) {
			var newItem = new PayloadItem {
				ExternalLength = extLength,
				Type = itemType,
				RelativePath = relPath,
				Encryption = !skipCrypto ? SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration
				             (SymmetricBlockCipher.Aes, BlockCipherMode.Ctr, BlockCipherPadding.None) : null
			};

			newItem.SetStreamBinding (() => itemData);
			return newItem;
		}

        
		private static SymmetricCipherConfiguration CreateDefaultBlockCipherConfiguration() {

		}

		/// <summary>
		/// Creates a default manifest key derivation configuration.
		/// </summary>
		/// <remarks>Default KDF configuration is scrypt</remarks>
		/// <returns>The default manifest key derivation.</returns>
		/// <param name="keyLengthBytes">Key length bytes.</param>
		private static KeyDerivationConfiguration CreateDefaultManifestKeyDerivation(int keyLengthBytes) {
			var schemeConfig = new ScryptConfiguration {
				IterationPower = 18,
				Blocks = 8,
				Parallelism = 2
			};
			var config = new KeyDerivationConfiguration {
				SchemeName = KeyDerivationFunction.Scrypt.ToString(),
				SchemeConfiguration = schemeConfig.SerialiseDTO(),
				Salt = new byte[keyLengthBytes]
			};
			StratCom.EntropySource.NextBytes(config.Salt);
			return config;
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

			if(Path.HasExtension(path)) {
				throw new ArgumentException ("Path is not a directory.");
			} else if (!dir.Exists) {
				throw new ArgumentException ("Directory does not exist.");
			}

            var rootPathLength = dir.FullName.Length;
            var files = dir.EnumerateFiles("*", search);
            foreach (var file in files) {
				var filePath = file.FullName; // provide consistent behaviour i.r.t. closure variable
				var itemStream = File.OpenRead (filePath);
				var itemRelPath = search == SearchOption.TopDirectoryOnly
				                  ? file.Name : file.FullName.Remove(0, rootPathLength + 1);
				if (Path.DirectorySeparatorChar != Athena.Packaging.PathDirectorySeperator) {
					itemRelPath = itemRelPath.Replace(Path.DirectorySeparatorChar, Athena.Packaging.PathDirectorySeperator);
				}
				var newItem = CreateItem (itemStream, PayloadItemTypes.Binary, file.Length, itemRelPath, false);

                _manifest.PayloadItems.Add(newItem);
            }
        }



		/// <summary>
		/// Reads a package manifest header (only) from a stream.
		/// </summary>
		/// <param name="source">Stream to read the header from.</param>
		/// <param name="mCryptoConfig">Manifest cryptography configuration deserialised from the header.</param>
		/// <param name="mCryptoScheme">Manifest cryptography scheme parsed from the header.</param>
		/// <returns>Package manifest header object.</returns>
		public static ManifestHeader ReadPackageManifestHeader(Stream source, out IManifestCryptographySchemeConfiguration mCryptoConfig,
			out ManifestCryptographySchemes mCryptoScheme)
		{
			Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadPackageManifestHeader", "[* PACKAGE START* ] Header offset (absolute)",
				source.Position.ToString()));

			var referenceHeaderTag = Athena.Packaging.GetHeaderTag();
			var readHeaderTag = new byte[referenceHeaderTag.Length];
			source.Read(readHeaderTag, 0, readHeaderTag.Length);
			if (!readHeaderTag.SequenceEqual(referenceHeaderTag)) {
				throw new InvalidDataException("Package is malformed. Expected header tag is either absent or malformed.");
			}

			Debug.Print(DebugUtility.CreateReportString("PackageReader", "ReadPackageManifestHeader", "Manifest header offset (absolute)",
				source.Position.ToString()));

			var mHeader = (ManifestHeader) StratCom.Serialiser.DeserializeWithLengthPrefix(source, null, typeof (ManifestHeader),
				PrefixStyle.Base128, 0);

			if (mHeader.FormatVersion > Athena.Packaging.HeaderVersion) {
				throw new NotSupportedException(String.Format("Package version {0} as specified by the manifest header is unsupported/unknown.\n" +
					"The local version of ObscurCore supports up to version {1}.", mHeader.FormatVersion, Athena.Packaging.HeaderVersion));
				// In later versions, can redirect to diff. behaviour (and DTO objects) for diff. versions.
			}

			mCryptoScheme = mHeader.CryptographySchemeName.ToEnum<ManifestCryptographySchemes>();
			switch (mHeader.CryptographySchemeName.ToEnum<ManifestCryptographySchemes>()) {
			case ManifestCryptographySchemes.UniversalSymmetric:
				mCryptoConfig = StratCom.DeserialiseDTO<SymmetricManifestCryptographyConfiguration>(mHeader.CryptographySchemeConfiguration);
				break;
			case ManifestCryptographySchemes.UM1Hybrid:
				mCryptoConfig = StratCom.DeserialiseDTO<UM1ManifestCryptographyConfiguration>(mHeader.CryptographySchemeConfiguration);
				break;
			case ManifestCryptographySchemes.Curve25519UM1Hybrid:
				mCryptoConfig = StratCom.DeserialiseDTO<Curve25519UM1ManifestCryptographyConfiguration>(mHeader.CryptographySchemeConfiguration);
				break;
			default:
				throw new NotSupportedException(String.Format(
					"Package manifest cryptography scheme \"{0}\" as specified by the manifest header is unsupported/unknown.", 
					mHeader.CryptographySchemeName));
			}

			return mHeader;
		}



        /// <summary>
        /// Read a package from a file.
        /// </summary>
        /// <returns></returns>
		public static Package FromFile(string filePath) {
            
        }

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


		/// <summary>
		/// Determines the offsets and read lengths of each individual item by simulating a demux
		/// </summary>
		private void BuildPayloadItemLayoutMap() {
			var remaining = new long[_manifest.PayloadItems.Count];

			var map = new List<MapSegment>();


			var itemSelector = Source.CreateCsprng(_manifest.PayloadConfiguration.PrimaryPRNGName.ToEnum<CsPseudorandomNumberGenerator>(),
				_manifest.PayloadConfiguration.PrimaryPRNGConfiguration);




		}

		struct MapSegment
		{
			Guid Item;
			long Offset;
			long Length;
		}






    }
}
