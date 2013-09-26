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
using System.Text;
using System.Threading.Tasks;
using ObscurCore.DTO;

namespace ObscurCore.Packaging
{
    /// <summary>
    /// [De]Multiplexer for stream sources/sinks. Mixes reads/writes among an arbitrary number of streams. 
    /// Uses asynchronous I/O and parallelised cryptographic processing.
    /// </summary>
    class AsyncCryptoMux
    {
        /// <summary>
        /// Persistent copy buffers.
        /// </summary>
        private readonly List<byte[]> _copyBuffers;

        private readonly Stream _multiplexed;
        private readonly List<IStreamBinding> _items = new List<IStreamBinding>();

        private readonly List<CyclicMemoryStream> _buffersAlpha = new List<CyclicMemoryStream>();
        private readonly List<CyclicMemoryStream> _buffersBeta = new List<CyclicMemoryStream>();


        private readonly List<Task> _tasksRead, _tasksProcess, _tasksWrite; 

        protected int Parallelism = Environment.ProcessorCount;

        public AsyncCryptoMux(Stream multiplexedStream, ICollection<PayloadItem> items) {
            
        }

        public async void Multiplex(Stream target, bool isEncrypting, ISymmetricCipherConfiguration config, byte[] key, 
		                              bool leaveOpen = false) {

        }

        public void Demultiplex() {
            
        }

        protected async void WorkerMethod() {
            
        }

    }
}
