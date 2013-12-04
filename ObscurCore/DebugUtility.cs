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

namespace ObscurCore
{
    /// <summary>
    /// Writes debugging messages in a standard format for easy viewing.
    /// </summary>
    public static class DebugUtility
    {
        public static string CreateReportString(string component, string locality, string description,
            string value, bool lineBreak = false)
        {
            var returnStr = String.Format("[{0}.{1}] {2} : {3}", component, locality, description, value);
            if (lineBreak) returnStr = returnStr + "\n";
            return returnStr;
        }

        public static string CreateReportString(string component, string locality, string description,
            int value, bool lineBreak = false)
        {
            return CreateReportString(component, locality, description, value.ToString());
        }

        public static string CreateReportString(string component, string locality, string description,
            long value, bool lineBreak = false)
        {
            return CreateReportString(component, locality, description, value.ToString());
        }
    }
}
