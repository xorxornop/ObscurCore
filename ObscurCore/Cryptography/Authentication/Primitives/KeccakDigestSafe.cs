//
//  Copyright 2014  Matthew Ducker
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

// Modified from https://bitbucket.org/jdluzen/sha3. Released under Modified BSD License.

using System;

namespace ObscurCore.Cryptography.Authentication.Primitives
{
#if !INCLUDE_UNSAFE
    public partial class KeccakDigest
    {
        private ulong[] _stateTemp;

        /// <inheritdoc />
        public void Update(byte input)
        {
            int sizeInBytes = ByteLength;
            int stride = sizeInBytes >> 3;
            if (BuffLength == sizeInBytes) {
                //buffer full
                if (_stateTemp == null) {
                    _stateTemp = new ulong[stride];
                }
                Buffer.BlockCopy(_buffer, 0, _stateTemp, 0, sizeInBytes);
                KeccakF(_stateTemp, stride);
                BuffLength = 0;
            }
            _buffer[BuffLength++] = input;
        }

        /// <inheritdoc />
        public void Reset()
        {
            BuffLength = 0;
            _buffer.SecureWipe();
            _state.SecureWipe();
            _stateTemp.SecureWipe();
        }

        private void HashCore(byte[] array, int offset, int length)
        {
            if (length == 0) {
                return;
            }
            int sizeInBytes = ByteLength;
            if (_buffer == null) {
                _buffer = new byte[sizeInBytes];
            }
            int stride = sizeInBytes >> 3;
            if (BuffLength == sizeInBytes) {
                throw new Exception("Unexpected error, the internal buffer is full");
            }
            AddToBuffer(array, ref offset, ref length);
            if (_stateTemp == null) {
                _stateTemp = new ulong[stride];
            }
            if (BuffLength == sizeInBytes) //buffer full
            {
                Buffer.BlockCopy(_buffer, 0, _stateTemp, 0, sizeInBytes);
                KeccakF(_stateTemp, stride);
                BuffLength = 0;
            }
            for (; length >= sizeInBytes; length -= sizeInBytes, offset += sizeInBytes) {
                Buffer.BlockCopy(array, offset, _stateTemp, 0, sizeInBytes);
                KeccakF(_stateTemp, stride);
            }
            if (length > 0) //some left over
            {
                array.CopyBytes(offset, _buffer, BuffLength, length);
                BuffLength += length;
            }
        }

        private void HashFinal(byte[] array, int offset)
        {
            int sizeInBytes = ByteLength;
            //    padding
            Array.Clear(_buffer, BuffLength, sizeInBytes - BuffLength);
            _buffer[BuffLength++] = 1;
            _buffer[sizeInBytes - 1] |= 0x80;
            int stride = sizeInBytes >> 3;
            if (_stateTemp == null) {
                _stateTemp = new ulong[stride];
            }
            Buffer.BlockCopy(_buffer, 0, _stateTemp, 0, sizeInBytes);
            KeccakF(_stateTemp, stride);
            Buffer.BlockCopy(_state, 0, array, offset, DigestSize);
        }

        private void KeccakF(ulong[] inb, int laneCount)
        {
            while (--laneCount >= 0) {
                _state[laneCount] ^= inb[laneCount];
            }
            ulong Aba, Abe, Abi, Abo, Abu;
            ulong Aga, Age, Agi, Ago, Agu;
            ulong Aka, Ake, Aki, Ako, Aku;
            ulong Ama, Ame, Ami, Amo, Amu;
            ulong Asa, Ase, Asi, Aso, Asu;
            ulong BCa, BCe, BCi, BCo, BCu;
            ulong Da, De, Di, Do, Du;
            ulong Eba, Ebe, Ebi, Ebo, Ebu;
            ulong Ega, Ege, Egi, Ego, Egu;
            ulong Eka, Eke, Eki, Eko, Eku;
            ulong Ema, Eme, Emi, Emo, Emu;
            ulong Esa, Ese, Esi, Eso, Esu;
            int round = laneCount;

            //copyFromState(A, _state)
            Aba = _state[0];
            Abe = _state[1];
            Abi = _state[2];
            Abo = _state[3];
            Abu = _state[4];
            Aga = _state[5];
            Age = _state[6];
            Agi = _state[7];
            Ago = _state[8];
            Agu = _state[9];
            Aka = _state[10];
            Ake = _state[11];
            Aki = _state[12];
            Ako = _state[13];
            Aku = _state[14];
            Ama = _state[15];
            Ame = _state[16];
            Ami = _state[17];
            Amo = _state[18];
            Amu = _state[19];
            Asa = _state[20];
            Ase = _state[21];
            Asi = _state[22];
            Aso = _state[23];
            Asu = _state[24];

            for (round = 0; round < KeccakNumberOfRounds; round += 2) {
                //    prepareTheta
                BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
                BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
                BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
                BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
                BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

                //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
                Da = BCu ^ ROL(BCe, 1);
                De = BCa ^ ROL(BCi, 1);
                Di = BCe ^ ROL(BCo, 1);
                Do = BCi ^ ROL(BCu, 1);
                Du = BCo ^ ROL(BCa, 1);

                Aba ^= Da;
                BCa = Aba;
                Age ^= De;
                BCe = ROL(Age, 44);
                Aki ^= Di;
                BCi = ROL(Aki, 43);
                Amo ^= Do;
                BCo = ROL(Amo, 21);
                Asu ^= Du;
                BCu = ROL(Asu, 14);
                Eba = BCa ^ ((~BCe) & BCi);
                Eba ^= RoundConstants[round];
                Ebe = BCe ^ ((~BCi) & BCo);
                Ebi = BCi ^ ((~BCo) & BCu);
                Ebo = BCo ^ ((~BCu) & BCa);
                Ebu = BCu ^ ((~BCa) & BCe);

                Abo ^= Do;
                BCa = ROL(Abo, 28);
                Agu ^= Du;
                BCe = ROL(Agu, 20);
                Aka ^= Da;
                BCi = ROL(Aka, 3);
                Ame ^= De;
                BCo = ROL(Ame, 45);
                Asi ^= Di;
                BCu = ROL(Asi, 61);
                Ega = BCa ^ ((~BCe) & BCi);
                Ege = BCe ^ ((~BCi) & BCo);
                Egi = BCi ^ ((~BCo) & BCu);
                Ego = BCo ^ ((~BCu) & BCa);
                Egu = BCu ^ ((~BCa) & BCe);

                Abe ^= De;
                BCa = ROL(Abe, 1);
                Agi ^= Di;
                BCe = ROL(Agi, 6);
                Ako ^= Do;
                BCi = ROL(Ako, 25);
                Amu ^= Du;
                BCo = ROL(Amu, 8);
                Asa ^= Da;
                BCu = ROL(Asa, 18);
                Eka = BCa ^ ((~BCe) & BCi);
                Eke = BCe ^ ((~BCi) & BCo);
                Eki = BCi ^ ((~BCo) & BCu);
                Eko = BCo ^ ((~BCu) & BCa);
                Eku = BCu ^ ((~BCa) & BCe);

                Abu ^= Du;
                BCa = ROL(Abu, 27);
                Aga ^= Da;
                BCe = ROL(Aga, 36);
                Ake ^= De;
                BCi = ROL(Ake, 10);
                Ami ^= Di;
                BCo = ROL(Ami, 15);
                Aso ^= Do;
                BCu = ROL(Aso, 56);
                Ema = BCa ^ ((~BCe) & BCi);
                Eme = BCe ^ ((~BCi) & BCo);
                Emi = BCi ^ ((~BCo) & BCu);
                Emo = BCo ^ ((~BCu) & BCa);
                Emu = BCu ^ ((~BCa) & BCe);

                Abi ^= Di;
                BCa = ROL(Abi, 62);
                Ago ^= Do;
                BCe = ROL(Ago, 55);
                Aku ^= Du;
                BCi = ROL(Aku, 39);
                Ama ^= Da;
                BCo = ROL(Ama, 41);
                Ase ^= De;
                BCu = ROL(Ase, 2);
                Esa = BCa ^ ((~BCe) & BCi);
                Ese = BCe ^ ((~BCi) & BCo);
                Esi = BCi ^ ((~BCo) & BCu);
                Eso = BCo ^ ((~BCu) & BCa);
                Esu = BCu ^ ((~BCa) & BCe);

                //    prepareTheta
                BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
                BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
                BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
                BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
                BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

                //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
                Da = BCu ^ ROL(BCe, 1);
                De = BCa ^ ROL(BCi, 1);
                Di = BCe ^ ROL(BCo, 1);
                Do = BCi ^ ROL(BCu, 1);
                Du = BCo ^ ROL(BCa, 1);

                Eba ^= Da;
                BCa = Eba;
                Ege ^= De;
                BCe = ROL(Ege, 44);
                Eki ^= Di;
                BCi = ROL(Eki, 43);
                Emo ^= Do;
                BCo = ROL(Emo, 21);
                Esu ^= Du;
                BCu = ROL(Esu, 14);
                Aba = BCa ^ ((~BCe) & BCi);
                Aba ^= RoundConstants[round + 1];
                Abe = BCe ^ ((~BCi) & BCo);
                Abi = BCi ^ ((~BCo) & BCu);
                Abo = BCo ^ ((~BCu) & BCa);
                Abu = BCu ^ ((~BCa) & BCe);

                Ebo ^= Do;
                BCa = ROL(Ebo, 28);
                Egu ^= Du;
                BCe = ROL(Egu, 20);
                Eka ^= Da;
                BCi = ROL(Eka, 3);
                Eme ^= De;
                BCo = ROL(Eme, 45);
                Esi ^= Di;
                BCu = ROL(Esi, 61);
                Aga = BCa ^ ((~BCe) & BCi);
                Age = BCe ^ ((~BCi) & BCo);
                Agi = BCi ^ ((~BCo) & BCu);
                Ago = BCo ^ ((~BCu) & BCa);
                Agu = BCu ^ ((~BCa) & BCe);

                Ebe ^= De;
                BCa = ROL(Ebe, 1);
                Egi ^= Di;
                BCe = ROL(Egi, 6);
                Eko ^= Do;
                BCi = ROL(Eko, 25);
                Emu ^= Du;
                BCo = ROL(Emu, 8);
                Esa ^= Da;
                BCu = ROL(Esa, 18);
                Aka = BCa ^ ((~BCe) & BCi);
                Ake = BCe ^ ((~BCi) & BCo);
                Aki = BCi ^ ((~BCo) & BCu);
                Ako = BCo ^ ((~BCu) & BCa);
                Aku = BCu ^ ((~BCa) & BCe);

                Ebu ^= Du;
                BCa = ROL(Ebu, 27);
                Ega ^= Da;
                BCe = ROL(Ega, 36);
                Eke ^= De;
                BCi = ROL(Eke, 10);
                Emi ^= Di;
                BCo = ROL(Emi, 15);
                Eso ^= Do;
                BCu = ROL(Eso, 56);
                Ama = BCa ^ ((~BCe) & BCi);
                Ame = BCe ^ ((~BCi) & BCo);
                Ami = BCi ^ ((~BCo) & BCu);
                Amo = BCo ^ ((~BCu) & BCa);
                Amu = BCu ^ ((~BCa) & BCe);

                Ebi ^= Di;
                BCa = ROL(Ebi, 62);
                Ego ^= Do;
                BCe = ROL(Ego, 55);
                Eku ^= Du;
                BCi = ROL(Eku, 39);
                Ema ^= Da;
                BCo = ROL(Ema, 41);
                Ese ^= De;
                BCu = ROL(Ese, 2);
                Asa = BCa ^ ((~BCe) & BCi);
                Ase = BCe ^ ((~BCi) & BCo);
                Asi = BCi ^ ((~BCo) & BCu);
                Aso = BCo ^ ((~BCu) & BCa);
                Asu = BCu ^ ((~BCa) & BCe);
            }

            //copyToState(_state, A)
            _state[0] = Aba;
            _state[1] = Abe;
            _state[2] = Abi;
            _state[3] = Abo;
            _state[4] = Abu;
            _state[5] = Aga;
            _state[6] = Age;
            _state[7] = Agi;
            _state[8] = Ago;
            _state[9] = Agu;
            _state[10] = Aka;
            _state[11] = Ake;
            _state[12] = Aki;
            _state[13] = Ako;
            _state[14] = Aku;
            _state[15] = Ama;
            _state[16] = Ame;
            _state[17] = Ami;
            _state[18] = Amo;
            _state[19] = Amu;
            _state[20] = Asa;
            _state[21] = Ase;
            _state[22] = Asi;
            _state[23] = Aso;
            _state[24] = Asu;
        }
    }
#endif
}
