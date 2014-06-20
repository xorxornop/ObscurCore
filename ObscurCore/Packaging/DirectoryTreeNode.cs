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
    public sealed class DirectoryTreeNode<T> : TreeNode<T>
    {
        private readonly bool _root;

        public DirectoryTreeNode(string name, DirectoryTreeNode<T> parent)
        {
            _root = false;
            Name = name;
            Parent = parent;
        }

        /// <summary>
        /// Creates a root directory node.
        /// </summary>
        internal DirectoryTreeNode()
        {
            _root = true;
            Name = "";
            Parent = null;
        }

        public bool IsRoot()
        {
            Debug.Assert((Parent == null) == _root);
            return _root;
        }

        private readonly List<TreeNode<T>> _children = new List<TreeNode<T>>();

        public IList<TreeNode<T>> Children
        {
            get { return _children; }
        }

        public bool HasChildren
        {
            get { return _children != null && (_children != null || _children.Count > 0); }
        }

        public DirectoryTreeNode<T> AddChildDirectory(string name)
        {
            var node = new DirectoryTreeNode<T>(name, this);
            _children.Add(node);
            return node;
        }

        public ContentTreeNode<T> AddChildItem(string name, T content)
        {
            var node = new ContentTreeNode<T>(name, this, content);
            _children.Add(node);
            return node;
        }

        internal TreeNode<T> AddChildNode(TreeNode<T> node)
        {
            node.Parent = this;
            _children.Add(node);
            return node;
        }

        public void RemoveChildNode(TreeNode<T> node, bool moveChildrenToParent)
        {
            var index = _children.IndexOf(node);
            if (index == -1) {
                //throw new ArgumentException("Specified node not present.", "node");
                return;
            }
            RemoveChildNode(index, moveChildrenToParent);
        }

        public void RemoveChildNode(string name, bool moveChildrenToParent)
        {
            var index = _children.FindIndex(child => child.Name.Equals(name));
            if (index == -1) {
                //throw new ArgumentException("Node with specified name not present.", "name");
                return;
            }
            RemoveChildNode(index, moveChildrenToParent);
        }

        public void RemoveChildNode(int index, bool moveChildrenToParent)
        {
            if (_children.Count <= index) {
                //throw new ArgumentException("Node of specified index not present (index is larger than collection length.", "index");
                return;
            }

            var node = _children[index];
            if (moveChildrenToParent && node is DirectoryTreeNode<T>) {
                var dirNode = node as DirectoryTreeNode<T>;
                foreach (var childNode in dirNode.Children) {
                    childNode.Parent = this;
                    _children.Add(childNode);
                }
            }
            _children.RemoveAt(index);
        }

        public int FindChildNodeIndex(string name)
        {
            return _children.FindIndex(child => child.Name.Equals(name));
        }

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
                var item = stack.Peek();
                if (item.MoveNext()) {
                    var current = item.Current;
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
