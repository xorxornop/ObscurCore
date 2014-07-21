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

namespace ObscurCore.Packaging
{
    /// <summary>
    ///     Node in a tree representing a discrete content item.
    /// </summary>
    /// <typeparam name="T">Type of data stored in node.</typeparam>
    public class ContentTreeNode<T> : TreeNode<T>
    {
        private T _content;

        /// <summary>
        ///     Creates a new content node.
        /// </summary>
        /// <param name="name">Name of the node.</param>
        /// <param name="parent">Parent of the node.</param>
        /// <param name="content">Content stored in the node.</param>
        /// <param name="mutable">If <c>true</c>, node can be modified after creation.</param>
        public ContentTreeNode(string name, DirectoryTreeNode<T> parent, T content, bool mutable = true) 
            : base(mutable)
        {
            Name = name;
            Parent = parent;
            Content = content;
        }

        /// <summary>
        ///     Content stored in the node.
        /// </summary>
        public T Content
        {
            get { return _content; }
            set {
                ThrowIfImmutable();
                _content = value;
            }
        }
    }
}
