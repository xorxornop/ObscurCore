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
using System.IO;
using ObscurCore.Extensions.Streams;

namespace ObscurCore.Packaging
{
#if(INCLUDE_FABRIC)
    public static class FabricConfigurationUtility
    {
        /// <summary>
        /// Reads an Fabric payload layout configuration from shorthand byte array format.
        /// </summary>
        /// <param name='config'>
        /// Config byte array.
        /// </param>
        /// <param name='minLength'>
        /// External variable for minimum size of a stripe in the Fabric layout.
        /// </param>
        /// <param name='maxLength'>
        /// External variable for maximum size of a stripe in the Fabric layout.
        /// </param>
        public static void Read (byte[] config, out int minLength, out int maxLength) {
            if (config.Length > 8) throw new ArgumentException("Configuration is invalid, over 8 bytes."); // FIXME
            using (var ms = new MemoryStream(config)) {
                ms.ReadPrimitive(out minLength);
                ms.ReadPrimitive(out maxLength);
            }
            if (!minLength.IsBetween(FabricMux.MinimumStripeLength, maxLength))
                throw new ArgumentOutOfRangeException("minLength", "Minimum stripe length is outside of specification limits.");
            if (!maxLength.IsBetween(minLength, FabricMux.MaximumStripeLength))
                throw new ArgumentOutOfRangeException("maxLength", "Maximum stripe length is outside of specification limits.");
        }

        /// <summary>
        /// Writes an Fabric payload layout configuration in shorthand byte array format.
        /// </summary>
        /// <returns>Byte array containing the configuration.</returns>
        /// <param name='fixedLength'>Size of a stripe in the Fabric layout.</param>
        public static byte[] WriteFixedStriping (int fixedLength) {
            if (!fixedLength.IsBetween(FabricMux.MinimumStripeLength, FabricMux.MaximumStripeLength))
                throw new ArgumentOutOfRangeException("fixedLength", "Requested fixed stripe length is outside of specification limits.");

            var ms = new MemoryStream();
            ms.WritePrimitive(fixedLength);
            ms.WritePrimitive(fixedLength);
            return ms.ToArray();
        }

        /// <summary>
        /// Writes an Fabric payload layout configuration in shorthand byte array format.
        /// </summary>
        /// <returns>Byte array containing the configuration.</returns>
        /// <param name='minLength'>Minimum size of a varied stripe in the Fabric layout.</param>
        /// <param name='maxLength'>Maximum size of a varied stripe in the Fabric layout.</param>
        public static byte[] WriteVariableStriping (int minLength, int maxLength) {
			if (minLength < FabricMux.MinimumStripeLength)
                throw new ArgumentOutOfRangeException("minLength", "Requested minimum varied stripe length is outside of specification limits.");
			if (maxLength > FabricMux.MaximumStripeLength)
                throw new ArgumentOutOfRangeException("maxLength", "Requested maximum varied stripe length is outside of specification limits.");

            var ms = new MemoryStream();
            ms.WritePrimitive(minLength);
            ms.WritePrimitive(maxLength);
            return ms.ToArray();
        }

        /// <summary>
        /// Verifies which striping mode is used from the combinations of primitive variables in the configuration.
        /// </summary>
        /// <param name='minLength'>Minimum size of a stripe in the Fabric layout.</param>
        /// <param name='maxLength'>Maximum size of a stripe in the Fabric layout.</param>
        public static FabricStripeModes CheckMode (int minLength, int maxLength) {
            return minLength.Equals(maxLength) ? FabricStripeModes.FixedLength : FabricStripeModes.VariableLength;
        }
    }
#endif


    public static class FrameshiftConfigurationUtility
    {
        /// <summary>
        /// Reads a Frameshift payload layout configuration from shorthand byte array format.
        /// </summary>
        /// <param name='config'>
        /// Config byte array.
        /// </param>
        /// <param name='minLength'>
        /// External variable for minimum size of the varied padding in the Frameshift layout.
        /// </param>
        /// <param name='maxLength'>
        /// External variable for maximum size of the varied padding in the Frameshift layout.
        /// </param>
        public static void Read (byte[] config, out int minLength, out int maxLength) {
            if (config.Length > 4) throw new ArgumentException("Configuration is invalid, over 4 bytes.");
            using (var ms = new MemoryStream(config)) {
                ushort min, max;
                ms.ReadPrimitive(out min);
                ms.ReadPrimitive(out max);
                minLength = min;
                maxLength = max;
            }
			if (!minLength.IsBetween(FrameshiftMux.MinimumPaddingLength, maxLength))
                throw new ArgumentOutOfRangeException("minLength", "Minimum stripe length is outside of specification limits.");
            if (!maxLength.IsBetween(minLength, FrameshiftMux.MaximumPaddingLength))
                throw new ArgumentOutOfRangeException("maxLength", "Maximum stripe length is outside of specification limits.");
        }

        /// <summary>
        /// Writes a Frameshift payload layout configuration in shorthand byte array format.
        /// </summary>
        /// <returns>Byte array containing the configuration.</returns>
        /// <param name='fixedLength'>Size of the padding in the Frameshift layout.</param>
        public static byte[] WriteFixedPadding (int fixedLength) {
			if (!fixedLength.IsBetween(FrameshiftMux.MinimumPaddingLength, FrameshiftMux.MaximumPaddingLength))
                throw new ArgumentOutOfRangeException("fixedLength", "Requested fixed stripe length is outside of specification limits.");
            var ms = new MemoryStream();
            ms.WritePrimitive((ushort) fixedLength);
            ms.WritePrimitive((ushort) fixedLength);
            return ms.ToArray();
        }

        /// <summary>
        /// Writes an Frameshift payload layout configuration in shorthand byte array format.
        /// </summary>
        /// <returns>Byte array containing the configuration.</returns>
        /// <param name='minLength'>Minimum size of the varied-length padding in the Frameshift layout.</param>
        /// <param name='maxLength'>Maximum size of the varied-length padding in the Frameshift layout.</param>
        public static byte[] WriteVariablePadding (int minLength, int maxLength) {
			if (minLength < FrameshiftMux.MinimumPaddingLength)
                throw new ArgumentOutOfRangeException("minLength", "Requested minimum varied padding length is outside of specification limits.");
			if (maxLength > FrameshiftMux.MaximumPaddingLength)
                throw new ArgumentOutOfRangeException("maxLength", "Requested maximum varied padding length is outside of specification limits.");

            var ms = new MemoryStream();
            ms.WritePrimitive((ushort) minLength);
            ms.WritePrimitive((ushort) maxLength);
            return ms.ToArray();
        }

        /// <summary>
        /// Verifies which padding mode is used from the combinations of primitive variables in the configuration.
        /// </summary>
        /// <param name='minLength'>Minimum size of the padding in the Frameshift layout.</param>
        /// <param name='maxLength'>Maximum size of the padding in the Frameshift layout.</param>
        public static FrameshiftPaddingModes CheckMode (int minLength, int maxLength) {
            return minLength.Equals(maxLength) ? FrameshiftPaddingModes.FixedLength : FrameshiftPaddingModes.VariableLength;
        }
    }
}
