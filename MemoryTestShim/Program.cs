using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using ObscurCore.Tests;
using ObscurCore.Tests.Packaging;

namespace MemoryTestShim
{
    class Program
    {
        static void Main(string[] args)
        {
            try {
                if (args[0] == "UM1FabricPackage") {
                    var tests = new Packages();
                    tests.UM1FabricPackage();
                } else if (args[0] == "UM1FabricSmallPackage") {
                    var tests = new Packages();
                    tests.UM1FabricSmallPackage();
                }
            } catch (SuccessException e) {
                Console.WriteLine(e);
            }
        }
    }
}
