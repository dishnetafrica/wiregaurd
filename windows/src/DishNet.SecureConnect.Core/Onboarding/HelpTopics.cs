using System.Reflection;

namespace DishNet.SecureConnect.Core.Onboarding;

public sealed record HelpTopic(string Title, string Body);

/// <summary>
/// The help centre content, parsed from the embedded help-topics.md
/// (one "## Title" per topic). The same Markdown file feeds the printed
/// customer manual, so the app and the manual never drift apart.
/// </summary>
public static class HelpTopics
{
    private static readonly Lazy<IReadOnlyList<HelpTopic>> Cache = new(Load);

    public static IReadOnlyList<HelpTopic> All => Cache.Value;

    public static HelpTopic? Find(string titleStartsWith) =>
        All.FirstOrDefault(t => t.Title.StartsWith(titleStartsWith, StringComparison.OrdinalIgnoreCase));

    public static string RawMarkdown()
    {
        using var s = typeof(HelpTopics).Assembly.GetManifestResourceStream("help-topics.md") ?? throw new InvalidOperationException("help-topics.md missing");
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }

    private static IReadOnlyList<HelpTopic> Load()
    {
        var topics = new List<HelpTopic>();
        string? title = null;
        var body = new List<string>();
        foreach (var raw in RawMarkdown().Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.StartsWith("## "))
            {
                if (title is not null) topics.Add(new HelpTopic(title, string.Join("\n", body).Trim()));
                title = line[3..].Trim();
                body.Clear();
            }
            else if (title is not null && !line.StartsWith("# ")) body.Add(line);
        }
        if (title is not null) topics.Add(new HelpTopic(title, string.Join("\n", body).Trim()));
        return topics;
    }

    /// <summary>Very small Markdown → plain-text conversion for WPF display (bold markers removed, lists kept).</summary>
    public static string ToPlainText(string markdown) => markdown.Replace("**", "");
}
