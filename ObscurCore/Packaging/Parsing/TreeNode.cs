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
using ObscurCore.DTO;

namespace ObscurCore.Packaging.Parsing
{
    /// <summary>
    ///     Base class for nodes in a tree representing a filesystem or other
    ///     similar hierarchical datastructure.
    /// </summary>
    /// <remarks>
    ///     Can be used for representing and manipulating a <see cref="PayloadItem" />
    ///     collection as a filesystem.
    /// </remarks>
    /// <typeparam name="T">Type of data stored in content/data nodes.</typeparam>
    public abstract class TreeNode<T> : IEquatable<TreeNode<T>>
    {
        private readonly Guid _identifier = new Guid();
        private bool _mutable;
        private string _name;
        private DirectoryTreeNode<T> _parent;

        /// <summary>
        ///     Create a new tree node.
        /// </summary>
        /// <param name="mutable">If <c>true</c>, node can be modified after creation.</param>
        protected TreeNode(bool mutable)
        {
            _mutable = mutable;
        }

        /// <summary>
        ///     Throws an <see cref="InvalidOperationException" /> if instance is set as immutable.
        /// </summary>
        /// <exception cref="InvalidOperationException">Attempted to modify immutable instance.</exception>
        protected void ThrowIfImmutable()
        {
            if (_mutable == false) {
                throw new InvalidOperationException("Cannot modify immutable object.");
            }
        }

        /// <summary>
        ///     Prohibits all future modification of the node (where <see cref="ThrowIfImmutable" /> is called).
        /// </summary>
        protected void SetImmutable()
        {
            _mutable = false;
        }

        /// <summary>
        ///     Name of node.
        /// </summary>
        public string Name
        {
            get { return _name; }
            set
            {
                ThrowIfImmutable();
                if (Parent != null && Parent.Children.Any(t => t.Name.Equals(_name))) {
                    throw new InvalidOperationException(
                        "The parent node already has a child node with this name. Cannot duplicate.");
                }
                _name = value;
            }
        }

        /// <summary>
        ///     Parent node.
        /// </summary>
        public DirectoryTreeNode<T> Parent
        {
            get { return _parent; }
            protected internal set
            {
                ThrowIfImmutable();
                _parent = value;
            }
        }

        /// <summary>
        ///     Unique identifier.
        /// </summary>
        public Guid Identifier
        {
            get { return _identifier; }
        }

        public bool Equals(TreeNode<T> other)
        {
            return Identifier.Equals(other.Identifier);
        }

        /// <summary>
        ///     Move node by reassigning its parent.
        /// </summary>
        /// <param name="newParent">Node to move this node to.</param>
        public void Move(DirectoryTreeNode<T> newParent)
        {
            ThrowIfImmutable();
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

        /// <summary>
        ///     Get the root of the tree.
        /// </summary>
        /// <returns>Root node.</returns>
        public TreeNode<T> GetRoot()
        {
            DirectoryTreeNode<T> node = (this as DirectoryTreeNode<T>) ?? Parent;
            while (node.IsRoot() == false) {
                node = node.Parent;
            }
            return node;
        }

        /// <summary>
        ///     Get the sequence of nodes from the root.
        /// </summary>
        /// <returns>Sequence of nodes.</returns>
        public IEnumerable<TreeNode<T>> GetPath()
        {
            var pathStack = new Stack<TreeNode<T>>();
            DirectoryTreeNode<T> node = (this as DirectoryTreeNode<T>) ?? Parent;
            while (node.IsRoot() == false) {
                pathStack.Push(node);
                node = node.Parent;
            }
            pathStack.Push(node);
            return pathStack;
        }

        /// <summary>
        ///     Recursively enumerates nested structure, but does so iteratively using a stack for efficiency.
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
                IEnumerator<TSrc> item = stack.Peek();
                if (item.MoveNext()) {
                    TSrc current = item.Current;
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
