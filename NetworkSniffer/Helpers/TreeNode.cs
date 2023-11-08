using System.Xml.Linq;

namespace NetworkSniffer.Helpers
{
    internal sealed class TreeNode
    {
        public string Text { get; }
        public NodesClass Nodes { get; }

        public TreeNode(string text)
        {
            Text = text;
            Nodes = new NodesClass();
        }

        public void Print() => Print(0);

        private void Print(int level = 0)
        {
            Console.WriteLine($"{new string(' ', level)} - {Text}");

            foreach (var node in Nodes.Nodes)
            {
                node.Print(level + 1);
            }
        }
    }

    internal sealed class NodesClass
    {
        private readonly List<TreeNode> _nodes;

        public IReadOnlyList<TreeNode> Nodes => _nodes;

        public NodesClass()
        {
            _nodes = new List<TreeNode>();
        }

        public void Add(TreeNode node) => _nodes.Add(node);

        public void Add(string text) => _nodes.Add(new TreeNode(text));
    }
}
