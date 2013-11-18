using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ObscurCore
{
    public static class DebugUtility
    {
        public static string CreateReportString(string component, string locality, string description,
            string value, bool lineBreak = false) {
            var returnStr = String.Format("[{0}.{1}] {2} : {3}", component, locality, description, value);
            if (lineBreak) returnStr = returnStr + "\n";
            return returnStr;
        }
    }
}
