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
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace ObscurCore.Packaging
{
    public abstract class TreeNode<T> : IEquatable<TreeNode<T>>
    {
        private string _name;

        public string Name
        {
            get { return _name; }
            set
            {
                if (Parent != null && Parent.Children.Any(t => t.Name.Equals(_name))) {
                    throw new InvalidOperationException(
                        "The parent node already has a child node with this name. Cannot duplicate.");
                }
                _name = value;
            }
        }

        public DirectoryTreeNode<T> Parent { get; protected internal set; }

        private readonly Guid _identifier = new Guid();

        public Guid Identifier
        {
            get { return _identifier; }
        }

        public void Move(DirectoryTreeNode<T> newParent)
        {
            if (newParent == null) {
                throw new ArgumentNullException("newParent");
            }
            if (Parent == null) {
                throw new InvalidOperationException("Node has no current parent. Cannot move.");
            }

            Debug.Assert(Parent.HasChildren);
            Parent.RemoveChildNode(this, false);
            Parent = newParent;
            Parent.AddChildNode(this);
        }

        public TreeNode<T> GetRoot()
        {
            var node = (this as DirectoryTreeNode<T>) ?? Parent;
            while (node.IsRoot() == false) {
                node = node.Parent;
            }
            return node;
        }

        public IEnumerable<TreeNode<T>> GetPath()
        {
            var pathStack = new Stack<TreeNode<T>>();
            var node = (this as DirectoryTreeNode<T>) ?? Parent;
            while (node.IsRoot() == false) {
                pathStack.Push(node);
                node = node.Parent;
            }
            pathStack.Push(node);
            return pathStack;
        }

        public bool Equals(TreeNode<T> other)
        {
            return Identifier.Equals(other.Identifier);
        }

        /// <summary>
        /// Recursively enumerates nested structure, but does so iteratively using a stack for efficiency.
        /// </summary>
        /// <typeparam name="TSrc">Type of source.</typeparam>
        /// <param name="source">Top-level source to enumerate.</param>
        /// <param name="selector">Selection function for choice of nested enumeration (what to enumerate).</param>
        /// <param name="emitPredicate">Basis of inclusion of a value into the end enumerable.</param>
        public static IEnumerable<TSrc> SelectRecursive<TSrc>(IEnumerable<TSrc> source,
            Func<TSrc, IEnumerable<TSrc>> selector, Func<TSrc, bool> emitPredicate)
        {
            if (source == null) {
                yield break;
            }

            var stack = new Stack<IEnumerator<TSrc>>();
            stack.Push(source.GetEnumerator());

            while (stack.Count > 0) {
                var item = stack.Peek();
                if (item.MoveNext()) {
                    var current = item.Current;
                    if (emitPredicate(current)) {
                        yield return item.Current;
                    }
                    stack.Push(selector(current).GetEnumerator());
                } else {
                    stack.Pop();
                }
            }
        }
    }
}
