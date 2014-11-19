using System;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
    /**
    * HMAC implementation based on RFC2104
    *
    * H(K XOR opad, H(K XOR ipad, text))
    */
    public class Hmac : MacEngine
    {
        private const byte Ipad = 0x36;
        private const byte Opad = 0x5C;

        private readonly IHash _digest;
        private readonly int _digestSize;
        private readonly int _blockLength;

        private readonly byte[] _inputPad;
        private readonly byte[] _outputPad;

        public Hmac(IHash digest) : base(MacFunction.Hmac)
        {
            this._digest = digest;
            this._digestSize = digest.OutputSize;
            this._blockLength = digest.StateSize;
            this._inputPad = new byte[_blockLength];
            this._outputPad = new byte[_blockLength];
        }

        /// <summary>
        ///     The size of operation in bytes the MAC function implements internally, e.g. block buffer.
        /// </summary>
        /// <value>The size of the internal operation in bytes.</value>
        public override int StateSize
        {
            get { return _blockLength; }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <remarks>
        ///     Returns for example 'HMAC-SHA-512' when using 
        ///     SHA-512 as the internal hash function.
        /// </remarks>
        public override string AlgorithmName
        {
            get { return base.AlgorithmName + "-" + _digest.AlgorithmName; }
        }

        /// <summary>
        ///     Display-friendly name of the MAC function.
        /// </summary>
        /// <value>The display name of the MAC function.</value>
        public override string DisplayName
        {
            get {
                var engine = _digest as HashEngine;
                if (engine != null) {
                    return base.DisplayName + " utilising " + engine.DisplayName;
                } else {
                    return base.DisplayName + " utilising " + _digest.AlgorithmName;
                }         
            }
        }

        public IHash UnderlyingDigest
        {
            get { return _digest; }
        }

        public override int OutputSize
        {
            get { return _digestSize; }
        }

        /// <summary>
        ///     Update the internal state of the MAC function with a single byte. 
        ///     Performs no checks on state validity - use only when pre-validated!
        /// </summary>
        /// <param name="input">Byte to input.</param>
        protected internal override void UpdateInternal(byte input)
        {
            _digest.Update(input);
        }

        /**
        * Reset the mac generator.
        */
        public override void Reset()
        {
            // Reset underlying digest
            _digest.Reset();
            _digest.BlockUpdate(_inputPad, 0, _inputPad.Length);
        }

        /// <summary>
        ///     Set up MAC function's internal state.
        /// </summary>
        protected override void InitState()
        {
            _digest.Reset();

            int keyLength = Key.Length;
            if (keyLength > _blockLength) {
                _digest.BlockUpdate(Key, 0, keyLength);
                _digest.DoFinal(_inputPad, 0);
                keyLength = _digestSize;
            } else {
                Array.Copy(Key, 0, _inputPad, 0, keyLength);
            }
            Array.Clear(_inputPad, keyLength, _blockLength - keyLength);
            Array.Copy(_inputPad, 0, _outputPad, 0, _blockLength);
            XorSingle(_inputPad, Ipad);
            XorSingle(_outputPad, Opad);

            _digest.BlockUpdate(_inputPad, 0, _inputPad.Length);
        }

        /// <summary>
        ///     Process bytes from <paramref name="input" />. 
        ///     Performs no checks on argument or state validity - use only when pre-validated!
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">
        ///     The offset in <paramref name="input" /> at which the input data begins.
        /// </param>
        /// <param name="length">The number of bytes to be processed.</param>
        protected internal override void BlockUpdateInternal(byte[] input, int inOff, int length)
        {
            var engine = _digest as HashEngine;
            if (engine != null) {
                engine.BlockUpdateInternal(input, inOff, length);
            } else {
                _digest.BlockUpdate(input, inOff, length);
            }
        }

        /// <summary>
        ///     Compute and output the final state, and reset the internal state of the MAC function. 
        ///     Performs no checks on argument or state validity - use only when pre-validated!
        /// </summary>
        /// <param name="output">Array that the MAC is to be output to.</param>
        /// <param name="outOff">
        ///     The offset into <paramref name="output" /> that the output is to start at.
        /// </param>
        /// <returns>Size of the output in bytes.</returns>
        protected internal override int DoFinalInternal(byte[] output, int outOff)
        {
            var tmp = new byte[_digestSize];
            var engine = _digest as HashEngine;
            if (engine != null) {
                engine.DoFinalInternal(tmp, 0);
                engine.BlockUpdateInternal(_outputPad, 0, _outputPad.Length);
                engine.BlockUpdateInternal(tmp, 0, tmp.Length);
                int len = engine.DoFinalInternal(output, outOff);
                _digest.BlockUpdate(_inputPad, 0, _inputPad.Length);
                return len;
            } else {          
                _digest.DoFinal(tmp, 0);
                _digest.BlockUpdate(_outputPad, 0, _outputPad.Length);
                _digest.BlockUpdate(tmp, 0, tmp.Length);
                int len = _digest.DoFinal(output, outOff);
                _digest.BlockUpdate(_inputPad, 0, _inputPad.Length);
                return len;
            }
        }

        private static void XorSingle(byte[] a, byte n)
        {
            for (int i = 0; i < a.Length; ++i) {
                a[i] ^= n;
            }
        }
    }
}
