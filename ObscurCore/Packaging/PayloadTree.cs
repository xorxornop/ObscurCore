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

using System;
using System.IO;
using System.Linq;
using System.Text;
using ObscurCore.DTO;

namespace ObscurCore.Packaging
{
    /// <summary>
    /// Utility for building and interpreting manifest payload contents 
    /// as hierarchal filesystem-type tree structures.
    /// </summary>
    public class PayloadTree
    {
        private const char DefaultPathSeperator = '/';
        protected char PathSeperator;
        protected char[] PathSeperators;
        private static readonly char[] InvalidPathChars = Path.GetInvalidPathChars();

        public DirectoryTreeNode<PayloadItem> RootNode { get; private set; }

        /// <summary>
        /// Create a new PayloadTree.
        /// </summary>
        /// <param name="seperator">Character that seperates directories and content in a path, e.g. <c>/</c>.</param>
        /// <param name="replaceSeperator">Character in a filesystem path to be replaced with <paramref name="seperator"/>.</param>
        public PayloadTree(char seperator = DefaultPathSeperator, char? replaceSeperator = null)
        {
            PathSeperator = seperator;
            PathSeperators = replaceSeperator == null
                ? new[] { PathSeperator }
                : new[] { PathSeperator, replaceSeperator.Value };
            RootNode = new DirectoryTreeNode<PayloadItem>();
        }

        /// <summary>
        /// Stores an item in the tree structure, building up 'directory' nodes as necessary in the process.
        /// </summary>
        /// <param name="item">Payload item to add as content.</param>
        /// <param name="path">Path of payload item.</param>
        /// <param name="checkForInvalid">If <c>true</c>, path will be checked for invalid characters.</param>
        public ContentTreeNode<PayloadItem> AddItem(PayloadItem item, string path, bool checkForInvalid = true)
        {
            if (String.IsNullOrWhiteSpace(path)) {
                throw new ArgumentException("Path is null, empty, or consists only of spaces.", "path");
            }

            var pathSegments = path.Split(PathSeperators, StringSplitOptions.RemoveEmptyEntries);
            if (pathSegments.Length == 0) {
                throw new ArgumentException("Path has no valid directory or item names.");
            }
            var dirNode = RootNode;

            for (var i = 0; i < pathSegments.Length; i++) {
                var segment = pathSegments[i];
                // Is this segment of the path already represented by a node?
                var matchIndex = -1;
                if (dirNode.HasChildren) {
                    matchIndex = dirNode.FindChildNodeIndex(segment);
                }
                if (matchIndex == -1) {
                    // Nope, it isn't! Have to make it.
                    // Maybe check if the path is valid
                    if (checkForInvalid && segment.Any(c => InvalidPathChars.Contains(c)) == false) {
                        throw new ArgumentException("Path contains invalid characters.", "path");
                    }

                    if (i == pathSegments.Length - 1) {
                        break;
                    }
                    dirNode = dirNode.AddChildDirectory(segment);
                } else {
                    if (i == pathSegments.Length - 1) {
                        if (dirNode.Children[matchIndex] is DirectoryTreeNode<PayloadItem>) {
                            throw new InvalidOperationException(
                                "Path terminator (content) is an existing directory name.");
                        }
                        throw new ArgumentException("Content of same name at this path already exists.", "path");
                    }
                    // Yes, already there, just change the reference.
                    dirNode = dirNode.Children[matchIndex] as DirectoryTreeNode<PayloadItem>;
                }
            }

            return new ContentTreeNode<PayloadItem>(pathSegments[pathSegments.Length - 1], dirNode, item);
        }

        /// <summary>
        /// Get the relative path of a node within this collection.
        /// </summary>
        /// <param name="item">Item to get path of.</param>
        /// <returns>Path of item within tree.</returns>
        public string GetPath(TreeNode<PayloadItem> item)
        {
            var nodePathEnumerable = item.GetPath();

            // Build path by popping path segments off stack
            var sb = new StringBuilder();
            foreach (var name in nodePathEnumerable) {
                sb.Append(PathSeperator);
                sb.Append(name);
            }

            return sb.ToString();
        }
    }
}
