using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace SourceLnked.SrcSrv;

internal class Parser
{
    private Dictionary<string, ImmutableArray<Node>> _variables = new();

    public bool UpsertVariable(string name, string input)
    {
        if (!Lexer.TryAnalyze(input, out var nodes))
            return false;
        if (!TryCreateAbstractSyntaxTree(nodes, out var astNodes))
            return false;
        _variables[name] = astNodes;
        return true;
    }

    public bool RemoveVariable(string name) => _variables.Remove(name);

    abstract record Node()
    {
        public abstract bool TryPrint(Parser parser, StringBuilder stringBuilder);

        public sealed record Literal(string Value) : Node
        {
            public override bool TryPrint(Parser parser, StringBuilder stringBuilder)
            {
                stringBuilder.Append(Value);
                return true;
            }
        }

        public sealed record Variable(string Name) : Node
        {
            public override bool TryPrint(Parser parser, StringBuilder stringBuilder)
            {
                if (!parser._variables.TryGetValue(Name, out var nodes))
                    return false;

                foreach (var node in nodes)
                {
                    if (!node.TryPrint(parser, stringBuilder))
                        return false;
                }

                return true;
            }

            public bool TryGetValue(Parser parser, [NotNullWhen(true)] out string? result)
            {
                if (!parser._variables.TryGetValue(Name, out var nodes))
                {
                    result = null;
                    return false;
                }
                StringBuilder stringBuilder = new StringBuilder();
                foreach (var node in nodes)
                {
                    if (!node.TryPrint(parser, stringBuilder))
                    {
                        result = null;
                        return false;
                    }
                }
                result = stringBuilder.ToString();
                return true;
            }
        }

        public sealed record FunctionCall(string Name, Variable Argument) : Node
        {
            public override bool TryPrint(Parser parser, StringBuilder stringBuilder)
            {
                if (!parser._variables.TryGetValue(Argument.Name, out var argumentNodes))
                    return false;
                if (!Argument.TryGetValue(parser, out string? argumentValue))
                    return false;

                switch (Name)
                {
                    case Constants.FunctionNameFnVar:
                        if (!parser._variables.TryGetValue(argumentValue, out var variableNodes))
                            return false;
                        foreach (var node in variableNodes)
                        {
                            if (!node.TryPrint(parser, stringBuilder))
                                return false;
                        }
                        return true;
                    case Constants.FunctionNameFnBksl:
                        stringBuilder.Append(argumentValue.Replace("/", "\\"));
                        return true;
                    case Constants.FunctionNameFnFile:
                        stringBuilder.Append(Path.GetFileName(argumentValue));
                        return true;
                    default:
                        return false;
                }
            }
        }
    }

    private static bool TryCreateAbstractSyntaxTree(List<Lexer.Node> lexerNodes, out ImmutableArray<Node> astNodes)
    {
        List<Node> astNodesStore = new List<Node>();
        for (int i = 0; i < lexerNodes.Count; i++)
        {
            switch (lexerNodes[i])
            {
                case Lexer.Node.Literal literal:
                    astNodesStore.Add(new Node.Literal(literal.Value));
                    break;
                case Lexer.Node.VariableOrFunctionMarker:
                    if (i + 2 >= lexerNodes.Count ||
                        lexerNodes[i + 1] is not Lexer.Node.Literal name ||
                        lexerNodes[i + 2] is not Lexer.Node.VariableOrFunctionMarker)
                    {
                        goto Failure;
                    }

                    i += 2;
                    if (i + 1 < lexerNodes.Count && lexerNodes[i + 1] is Lexer.Node.ArgumentStart)
                    {
                        // A supported function name is followed by (%variable%).
                        if (i + 5 >= lexerNodes.Count ||
                            lexerNodes[i + 2] is not Lexer.Node.VariableOrFunctionMarker ||
                            lexerNodes[i + 3] is not Lexer.Node.Literal argument ||
                            lexerNodes[i + 4] is not Lexer.Node.VariableOrFunctionMarker ||
                            lexerNodes[i + 5] is not Lexer.Node.ArgumentEnd)
                        {
                            goto Failure;
                        }

                        astNodesStore.Add(new Node.FunctionCall(name.Value, new Node.Variable(argument.Value)));
                        i += 5;
                    }
                    else
                    {
                        astNodesStore.Add(new Node.Variable(name.Value));
                    }
                    break;
                default:
                    goto Failure;
            }
        }

        astNodes = astNodesStore.ToImmutableArray();
        return true;

Failure:
        astNodes = ImmutableArray<Node>.Empty;
        return false;
    }

    public bool TryEvaluateVariable(string variableName, [NotNullWhen(true)] out string? result)
    {
        if (!_variables.TryGetValue(variableName, out var nodes))
        {
            goto Failure;
        }
        StringBuilder stringBuilder = new StringBuilder();
        foreach (var node in nodes)
        {
            if (!node.TryPrint(this, stringBuilder))
            {
                goto Failure;
            }
        }
        result = stringBuilder.ToString();
        return true;

Failure:
        result = null;
        return false;
    }
}