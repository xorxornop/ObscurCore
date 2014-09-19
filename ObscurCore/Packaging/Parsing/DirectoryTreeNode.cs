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

namespace ObscurCore.Packaging.Parsing
{
    /// <summary>
    ///     Node in a tree representing a directory, or index of other nodes.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public sealed class DirectoryTreeNode<T> : TreeNode<T>
    {
        private readonly List<TreeNode<T>> _children = new List<TreeNode<T>>();
        private readonly bool _root;

        /// <summary>
        ///     Creates a new directory node.
        /// </summary>
        /// <param name="name">Name of the directory.</param>
        /// <param name="parent">Parent of the node.</param>
        /// <param name="mutable">If <c>true</c>, node can be modified after creation.</param>
        public DirectoryTreeNode(string name, DirectoryTreeNode<T> parent, bool mutable = true) 
            : base(mutable)
        {
            _root = false;
            Name = name;
            Parent = parent;
        }

        /// <summary>
        ///     Creates a root directory node.
        /// </summary>
        internal DirectoryTreeNode(bool mutable = true)
            : base(mutable)
        {
            _root = true;
            Name = "";
            Parent = null;
        }

        /// <summary>
        ///     Nodes contained in the directory.
        /// </summary>
        public IList<TreeNode<T>> Children
        {
            get { return _children; }
        }

        /// <summary>
        /// If <c>true</c>, node contains child nodes.
        /// </summary>
        public bool HasChildren
        {
            get { return _children != null && (_children != null || _children.Count > 0); }
        }

        /// <summary>
        ///     If node is the root of the tree.
        /// </summary>
        /// <returns>If <c>true</c>, node is the root.</returns>
        public bool IsRoot()
        {
            Debug.Assert((Parent == null) == _root);
            return _root;
        }

        /// <summary>
        /// Add a subdirectory.
        /// </summary>
        /// <param name="name">Name of the directory to add.</param>
        /// <returns>Directory node.</returns>
        public DirectoryTreeNode<T> AddChildDirectory(string name)
        {
            ThrowIfImmutable();
            var node = new DirectoryTreeNode<T>(name, this);
            _children.Add(node);
            return node;
        }

        /// <summary>
        /// Add content to the directory.
        /// </summary>
        /// <param name="name">Name of the content.</param>
        /// <param name="content">Content to add.</param>
        /// <returns>Content tree node.</returns>
        public ContentTreeNode<T> AddChildItem(string name, T content)
        {
            ThrowIfImmutable();
            var node = new ContentTreeNode<T>(name, this, content);
            _children.Add(node);
            return node;
        }

        /// <summary>
        /// Add a node to the directory.
        /// </summary>
        /// <param name="node">Node to add.</param>
        /// <returns></returns>
        internal void AddChildNode(TreeNode<T> node)
        {
            ThrowIfImmutable();
            node.Parent = this;
            _children.Add(node);
        }

        /// <summary>
        /// Remove a node from the directory.
        /// </summary>
        /// <param name="node">Node to remove.</param>
        /// <param name="moveChildrenToParent">If <c>true</c>, move all children of removed node to this directory.</param>
        public void RemoveChildNode(TreeNode<T> node, bool moveChildrenToParent)
        {
            ThrowIfImmutable();
            int index = _children.IndexOf(node);
            if (index == -1) {
                //throw new ArgumentException("Specified node not present.", "node");
                return;
            }
            RemoveChildNode(index, moveChildrenToParent);
        }

        /// <summary>
        /// Remove a node from the directory by name.
        /// </summary>
        /// <param name="name">Name of the node to remove.</param>
        /// <param name="moveChildrenToParent">If <c>true</c>, move all children of removed node to this directory.</param>
        public void RemoveChildNode(string name, bool moveChildrenToParent)
        {
            ThrowIfImmutable();
            int index = _children.FindIndex(child => child.Name.Equals(name));
            if (index == -1) {
                throw new ArgumentException("Node with specified name not present.", "name");
            }
            RemoveChildNode(index, moveChildrenToParent);
        }

        /// <summary>
        /// Remove a node from the directory by index.
        /// </summary>
        /// <param name="index">Index of the node to remove.</param>
        /// <param name="moveChildrenToParent">If <c>true</c>, move all children of removed node to this directory.</param>
        public void RemoveChildNode(int index, bool moveChildrenToParent)
        {
            ThrowIfImmutable();
            if (index >= _children.Count) {
                throw new ArgumentException("Node of specified index not present (index is larger than collection length.", "index");
            }

            TreeNode<T> node = _children[index];
            if (moveChildrenToParent && node is DirectoryTreeNode<T>) {
                var dirNode = node as DirectoryTreeNode<T>;
                foreach (var childNode in dirNode.Children) {
                    childNode.Parent = this;
                    _children.Add(childNode);
                }
            }
            _children.RemoveAt(index);
        }

        /// <summary>
        /// Get the index of a child node of the directory by name.
        /// </summary>
        /// <param name="name">Name of the node to find.</param>
        /// <returns>Index of the node. -1 if not found.</returns>
        public int FindChildNodeIndex(string name)
        {
            return _children.FindIndex(child => child.Name.Equals(name));
        }

        /// <summary>
        ///     Get a sequence of all content tree nodes in the directory, 
        ///     optionally including subdirectories.
        /// </summary>
        /// <param name="recursive">If <c>true</c>, recursively include all subdirectory nodes.</param>
        /// <returns>Sequence of contained content nodes.</returns>
        public IEnumerable<ContentTreeNode<T>> GetContent(bool recursive)
        {
            IEnumerable<ContentTreeNode<T>> e;
            if (recursive) {
                e = SelectSubtypeRecursive<TreeNode<T>, DirectoryTreeNode<T>, ContentTreeNode<T>>(_children,
                    node => node.Children);
            } else {
                e = Children.OfType<ContentTreeNode<T>>();
            }
            return e;
        }

        /// <summary>
        ///     Recursively enumerates nested structure for a specific type, 
        ///     but does so iteratively using a stack for efficiency.
        /// </summary>
        /// <typeparam name="TBase">Type of objects to search.</typeparam>
        /// <typeparam name="TCollection">
        ///     Type containing collection of <typeparamref name="TBase"/>.
        /// </typeparam>
        /// <typeparam name="TSubtype">
        ///     Type to select from collections of <typeparamref name="TCollection"/>.
        /// </typeparam>
        /// <param name="source">Source of objects to search.</param>
        /// <param name="selector">
        ///     Predicate for inclusion of objects of type <typeparamref name="TSubtype"/> found.
        /// </param>
        /// <returns>Sequence of found objects of type <typeparamref name="TSubtype"/></returns>
        public static IEnumerable<TSubtype> SelectSubtypeRecursive<TBase, TCollection, TSubtype>(
            IEnumerable<TBase> source,
            Func<TCollection, IEnumerable<TBase>> selector) where TSubtype : class, TBase
            where TCollection : class, TBase
        {
            if (source == null) {
                yield break;
            }

            var stack = new Stack<IEnumerator<TBase>>();
            stack.Push(source.GetEnumerator());

            while (stack.Count > 0) {
                IEnumerator<TBase> item = stack.Peek();
                if (item.MoveNext()) {
                    TBase current = item.Current;
                    if (current is TSubtype) {
                        yield return item.Current as TSubtype;
                    } else if (current is TCollection) {
                        stack.Push(selector(current as TCollection).GetEnumerator());
                    }
                } else {
                    stack.Pop();
                }
            }
        }
    }
}
