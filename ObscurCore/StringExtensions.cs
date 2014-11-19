#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ObscurCore
{
    public static class StringExtensions
    {
        /// <summary>
        ///     Emits a string representation of a sequence of items, 
        ///     e.g. with default parameters and the sequence [A, B, C] => "{ A, B, C }" .
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="items">Sequence of items to create a string sequence-representation of.</param>
        /// <param name="delimiter">Character that delimits each item in the sequence.</param>
        /// <param name="start">Character that denotes the start of the sequence.</param>
        /// <param name="end">Character that denotes the end of the sequence.</param>
        /// <returns></returns>
        public static string AsDelimitedString<T>(this IEnumerable<T> items, char delimiter = ',', char start = '{',
                                                  char end = '}')
        {
            var sb = new StringBuilder();

            bool firstItem = true;
            string delimit = delimiter + " ";
            sb.Append(start + ' ');
            foreach (var item in items) {
                if (firstItem) {
                    sb.Append(item);
                    firstItem = false;
                } else {
                    sb.Append(delimit);
                    sb.Append(item);
                }
            }
            sb.Append(' ' + end);

            return sb.ToString();
        }
    }
}
