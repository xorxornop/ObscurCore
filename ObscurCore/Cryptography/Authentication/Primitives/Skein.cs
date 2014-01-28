/*
Copyright (c) 2009 Alberto Fajardo

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

using System;
using System.Security.Cryptography;

using ObscurCore.Cryptography.Ciphers.Block.Primitives;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
	public class Skein : IMac
	{
		private readonly ThreefishEngine _cipher;
		private readonly int _cipherStateBits;
		private readonly int _cipherStateBytes;
		private readonly int _cipherStateWords;

		private readonly int _outputBytes;

		private readonly byte[] _inputBuffer;
		private int _bytesFilled;

		private readonly ulong[] _cipherInput;
		private readonly ulong[] _state;

		public SkeinConfig Configuration { get; private set; }
		public UbiTweak UbiParameters { get; private set; }

		public int StateSize
		{
			get { return _cipherStateBits; }
		}

		/// <summary>
		/// Initializes the Skein hash instance.
		/// </summary>
		/// <param name="stateSize">The internal state size of the hash in bits.
		/// Supported values are 256, 512, and 1024.</param>
		/// <param name="outputSize">The output size of the hash in bits.
		/// Output size must be divisible by 8 and greater than zero.</param>
		public Skein(int stateSize, int outputSize)
		{
			// Make sure the output bit size > 0
			if (outputSize <= 0)
				throw new CryptoException("Output bit size must be greater than zero.");

			// Make sure output size is divisible by 8
			if (outputSize % 8 != 0)
				throw new CryptoException("Output bit size must be divisible by 8.");

			_cipherStateBits = stateSize;
			_cipherStateBytes = stateSize / 8;
			_cipherStateWords = stateSize / 64;

			_outputBytes = (outputSize + 7) / 8;

			// Figure out which cipher we need based on
			// the state size
			_cipher = ThreefishEngine.CreateCipher(stateSize);
			if (_cipher == null) throw new CryptographicException("Unsupported state size.");

			// Allocate buffers
			_inputBuffer = new byte[_cipherStateBytes];
			_cipherInput = new ulong[_cipherStateWords];
			_state = new ulong[_cipherStateWords];

			// Allocate tweak
			UbiParameters = new UbiTweak();

			// Generate the configuration string
			Configuration = new SkeinConfig(this);
			Configuration.SetSchema(83, 72, 65, 51); // "SHA3"
			Configuration.SetVersion(1);
			Configuration.GenerateConfiguration();
		}

		/// <summary>
		/// Creates the initial state with zeros instead of the configuration block, then initializes the hash.
		/// This does not start a new UBI block type, and must be done manually.
		/// </summary>
		public void Initialize(SkeinInitializationType initializationType)
		{
			switch(initializationType)
			{
			case SkeinInitializationType.Normal:
				// Normal initialization
				Init(null);
				return;

			case SkeinInitializationType.ZeroedState:
				// Copy the configuration value to the state
				for (int i = 0; i < _state.Length; i++)
					_state[i] = 0;
				break;

			case SkeinInitializationType.ChainedState:
				// Keep the state as it is and do nothing
				break;

			case SkeinInitializationType.ChainedConfig:
				// Generate a chained configuration
				Configuration.GenerateConfiguration(_state);
				// Continue initialization
				Init(null);
				return;
			}

			// Reset bytes filled
			_bytesFilled = 0;
		}

		#region IMac implementation

		public void Init (byte[] key)
		{
			// Copy the configuration value to the state
			for (int i = 0; i < _state.Length; i++)
				_state[i] = Configuration.ConfigValue[i];

			// Set up tweak for message block
			UbiParameters.StartNewBlockType(UbiType.Message);

			// Reset bytes filled
			_bytesFilled = 0;
		}


		public void Update (byte input)
		{
			_inputBuffer[_bytesFilled++] = input;

			// Do a transform if the input buffer is filled
			if (_bytesFilled == _cipherStateBytes)
			{
				// Copy input buffer to cipher input buffer
				InputBufferToCipherInput();

				// Process the block
				ProcessBlock(_cipherStateBytes);

				// Clear first flag, which will be set
				// by Initialize() if this is the first transform
				UbiParameters.IsFirstBlock = false;

				// Reset buffer fill count
				_bytesFilled = 0;
			}
		}

		public void BlockUpdate (byte[] input, int inOff, int len) {
			int bytesDone = 0;
			int offset = inOff;

			// Fill input buffer
			while (bytesDone < len && offset < input.Length)
			{
				// Do a transform if the input buffer is filled
				if (_bytesFilled == _cipherStateBytes)
				{
					// Copy input buffer to cipher input buffer
					InputBufferToCipherInput();

					// Process the block
					ProcessBlock(_cipherStateBytes);

					// Clear first flag, which will be set
					// by Initialize() if this is the first transform
					UbiParameters.IsFirstBlock = false;

					// Reset buffer fill count
					_bytesFilled = 0;
				}

				_inputBuffer[_bytesFilled++] = input[offset++];
				bytesDone++;
			}
		}

		public int DoFinal (byte[] output, int outOff) {
			int i;

			// Pad left over space in input buffer with zeros
			// and copy to cipher input buffer
			for (i = _bytesFilled; i < _inputBuffer.Length; i++)
				_inputBuffer[i] = 0;

			InputBufferToCipherInput();

			// Do final message block
			UbiParameters.IsFinalBlock = true;
			ProcessBlock(_bytesFilled);

			// Clear cipher input
			for (i = 0; i < _cipherInput.Length; i++)
				_cipherInput[i] = 0;

			// Do output block counter mode output
			int j;

			//var hash = new byte[_outputBytes];
			var oldState = new ulong[_cipherStateWords];

			// Save old state
			for (j = 0; j < _state.Length; j++)
				oldState[j] = _state[j];

			for (i = 0; i < _outputBytes; i += _cipherStateBytes)
			{
				UbiParameters.StartNewBlockType(UbiType.Out);
				UbiParameters.IsFinalBlock = true;
				ProcessBlock(8);

				// Output a chunk of the hash
				int outputSize = _outputBytes - i;
				if (outputSize > _cipherStateBytes)
					outputSize = _cipherStateBytes;

				PutBytes(_state, output, outOff + i, outputSize);

				// Restore old state
				for (j = 0; j < _state.Length; j++)
					_state[j] = oldState[j];

				// Increment counter
				_cipherInput[0]++;
			}

			//return hash;
			return _outputBytes;
		}

		public void Reset ()
		{
			throw new NotImplementedException ();
		}

		public string AlgorithmName {
			get {
				return "Skein" + _outputBytes * 8;
			}
		}

		public int MacSize {
			get {
				return _outputBytes;
			}
		}

		#endregion

		void ProcessBlock(int bytes)
		{
			// Set the key to the current state
			_cipher.SetKey(_state);

			// Update tweak
			UbiParameters.BitsProcessed += (ulong) bytes;
			_cipher.SetTweak(UbiParameters.Tweak);

			// Encrypt block
			_cipher.Encrypt(_cipherInput, _state);

			// Feed-forward input with state
			for (int i = 0; i < _cipherInput.Length; i++)
				_state[i] ^= _cipherInput[i];
		}

		// Moves the byte input buffer to the ulong cipher input
		void InputBufferToCipherInput()
		{
			for (int i = 0; i < _cipherStateWords; i++)
				_cipherInput[i] = GetUInt64(_inputBuffer, i * 8);
		}

		#region Utils
		static ulong GetUInt64(byte[] buf, int offset)
		{
			ulong v;
			v = (ulong)buf[offset];
			v |= (ulong)buf[offset + 1] << 8;
			v |= (ulong)buf[offset + 2] << 16;
			v |= (ulong)buf[offset + 3] << 24;
			v |= (ulong)buf[offset + 4] << 32;
			v |= (ulong)buf[offset + 5] << 40;
			v |= (ulong)buf[offset + 6] << 48;
			v |= (ulong)buf[offset + 7] << 56;
			return v;
		}

		static void GetBytes(byte[] input, int offset, ulong[] output, int byte_count)
		{
			for (int i = 0; i < byte_count; i += 8)
			{
				output[i / 8] = GetUInt64(input, i + offset);
			}
		}

		static void PutBytes(ulong[] input, byte[] output, int offset, int byte_count)
		{
			int j = 0;
			for (int i = 0; i < byte_count; i++)
			{
				//PutUInt64(output, i + offset, input[i / 8]);
				output[offset + i] = (byte) ((input[i / 8] >> j) & 0xff);
				j = (j + 8) % 64;
			}
		}

		#endregion

		// Supporting classes etc.

		/// <summary>
		/// Specifies the Skein initialization type.
		/// </summary>
		public enum SkeinInitializationType
		{
			/// <summary>
			/// Identical to the standard Skein initialization.
			/// </summary>
			Normal,

			/// <summary>
			/// Creates the initial state with zeros instead of the configuration block, then initializes the hash.
			/// This does not start a new UBI block type, and must be done manually.
			/// </summary>
			ZeroedState,

			/// <summary>
			/// Leaves the initial state set to its previous value, which is then chained with subsequent block transforms.
			/// This does not start a new UBI block type, and must be done manually.
			/// </summary>
			ChainedState,

			/// <summary>
			/// Creates the initial state by chaining the previous state value with the config block, then initializes the hash.
			/// This starts a new UBI block type with the standard Payload type.
			/// </summary>
			ChainedConfig
		}

		public class SkeinConfig
		{
			private readonly int _stateSize;

			public SkeinConfig(Skein sourceHash)
			{
				_stateSize = sourceHash.StateSize;

				// Allocate config value
				ConfigValue = new ulong[sourceHash.StateSize / 8];

				// Set the state size for the configuration
				ConfigString = new ulong[ConfigValue.Length];
				ConfigString[1] = (ulong) sourceHash.MacSize;
			}

			public void GenerateConfiguration()
			{
				var cipher = ThreefishEngine.CreateCipher(_stateSize);
				var tweak = new UbiTweak();

				// Initialize the tweak value
				tweak.StartNewBlockType(UbiType.Config);
				tweak.IsFinalBlock = true;
				tweak.BitsProcessed = 32;

				cipher.SetTweak(tweak.Tweak);
				cipher.Encrypt(ConfigString, ConfigValue);

				ConfigValue[0] ^= ConfigString[0]; 
				ConfigValue[1] ^= ConfigString[1];
				ConfigValue[2] ^= ConfigString[2];
			}

			public void GenerateConfiguration(ulong[] initialState)
			{
				var cipher = ThreefishEngine.CreateCipher(_stateSize);
				var tweak = new UbiTweak();

				// Initialize the tweak value
				tweak.StartNewBlockType(UbiType.Config);
				tweak.IsFinalBlock = true;
				tweak.BitsProcessed = 32;

				cipher.SetKey(initialState);
				cipher.SetTweak(tweak.Tweak);
				cipher.Encrypt(ConfigString, ConfigValue);

				ConfigValue[0] ^= ConfigString[0];
				ConfigValue[1] ^= ConfigString[1];
				ConfigValue[2] ^= ConfigString[2];
			}

			public void SetSchema(params byte[] schema)
			{
				if (schema.Length != 4) throw new Exception("Schema must be 4 bytes.");

				ulong n = ConfigString[0];

				// Clear the schema bytes
				n &= ~(ulong)0xfffffffful;
				// Set schema bytes
				n |= (ulong) schema[3] << 24;
				n |= (ulong) schema[2] << 16;
				n |= (ulong) schema[1] << 8;
				n |= (ulong) schema[0];

				ConfigString[0] = n;
			}

			public void SetVersion(int version)
			{
				if (version < 0 || version > 3)
					throw new Exception("Version must be between 0 and 3, inclusive.");

				ConfigString[0] &= ~((ulong)0x03 << 32);
				ConfigString[0] |= (ulong)version << 32;
			}

			public void SetTreeLeafSize(byte size)
			{
				ConfigString[2] &= ~(ulong)0xff;
				ConfigString[2] |= (ulong)size;
			}

			public void SetTreeFanOutSize(byte size)
			{
				ConfigString[2] &= ~((ulong)0xff << 8);
				ConfigString[2] |= (ulong)size << 8;
			}

			public void SetMaxTreeHeight(byte height)
			{
				if (height == 1)
					throw new Exception("Tree height must be zero or greater than 1.");

				ConfigString[2] &= ~((ulong)0xff << 16);
				ConfigString[2] |= (ulong)height << 16;
			}

			public ulong[] ConfigValue { get; private set; }

			public ulong[] ConfigString { get; private set; }
		}

		public enum UbiType : ulong
		{
			Key = 0,
			Config = 4,
			Personalization = 8,
			PublicKey = 16,
			Nonce = 20,
			Message = 48,
			Out = 63
		}

		public class UbiTweak
		{
			private const ulong T1FlagFinal = unchecked((ulong)1 << 63);
			private const ulong T1FlagFirst = unchecked((ulong)1 << 62);

			public UbiTweak()
			{
				Tweak = new ulong[2];
			}

			/// <summary>
			/// Gets or sets the first block flag.
			/// </summary>
			public bool IsFirstBlock
			{
				get { return (Tweak[1] & T1FlagFirst) != 0; }
				set
				{
					long mask = value ? 1 : 0;
					Tweak[1] = (Tweak[1] & ~T1FlagFirst) | ((ulong)-mask & T1FlagFirst);
				}
			}

			/// <summary>
			/// Gets or sets the final block flag.
			/// </summary>
			public bool IsFinalBlock
			{
				get { return (Tweak[1] & T1FlagFinal) != 0; }
				set
				{
					long mask = value ? 1 : 0;
					Tweak[1] = (Tweak[1] & ~T1FlagFinal) | ((ulong)-mask & T1FlagFinal);
				}
			}

			/// <summary>
			/// Gets or sets the current tree level.
			/// </summary>
			public byte TreeLevel
			{
				get { return (byte) ((Tweak[1] >> 48) & 0x3f); }
				set
				{
					if (value > 63)
						throw new Exception("Tree level must be between 0 and 63, inclusive.");

					Tweak[1] &= ~((ulong) 0x3f << 48);
					Tweak[1] |= (ulong) value << 48;
				}
			}

			/// <summary>
			/// Gets or sets the number of bits processed so far, inclusive.
			/// </summary>
			public ulong BitsProcessed
			{
				get { return Tweak[0]; }
				set { Tweak[0] = value; }
			}

			/// <summary>
			/// Gets or sets the current UBI block type.
			/// </summary>
			public UbiType BlockType
			{
				get { return (UbiType) (Tweak[1] >> 56); }
				set { Tweak[1] = (ulong)value << 56; }
			}

			/// <summary>
			/// Starts a new UBI block type by setting BitsProcessed to zero, setting the first flag, and setting the block type.
			/// </summary>
			/// <param name="type">The UBI block type of the new block.</param>
			public void StartNewBlockType(UbiType type)
			{
				BitsProcessed = 0;
				BlockType = type;
				IsFirstBlock = true;
			}

			/// <summary>
			/// The current Threefish tweak value.
			/// </summary>
			public ulong[] Tweak { get; private set; }
		}
	}
}