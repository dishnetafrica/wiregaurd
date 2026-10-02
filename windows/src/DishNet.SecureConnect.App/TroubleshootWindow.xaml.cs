using System.Windows;
using DishNet.SecureConnect.Core.Onboarding;

namespace DishNet.SecureConnect.App;

/// <summary>Question flow over Core.Troubleshooter: observable layers are decided automatically, the rest asked one question at a time.</summary>
public partial class TroubleshootWindow : Window
{
    private readonly MainViewModel _vm;
    private TroubleshootAnswers _answers = new();
    private Diagnosis? _last;

    public TroubleshootWindow(MainViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        Loaded += async (_, _) => { await _vm.RefreshAsync(); Render(); };
    }

    private void Render()
    {
        Observed.Text = _vm.ObservedSummary;
        var d = _vm.Diagnose(_answers);
        _last = d;
        QuestionBox.Visibility = d.NeedsAnswer ? Visibility.Visible : Visibility.Collapsed;
        Question.Text = d.NextQuestion ?? "";
        LayerText.Text = d.Layer switch
        {
            FailureLayer.None => "All layers OK",
            FailureLayer.Activation => "Layer 1 of 6 · Activation",
            FailureLayer.Vpn => "Layer 2 of 6 · DishNet connection",
            FailureLayer.OfficePc => "Layer 3 of 6 · Office computer",
            FailureLayer.RemoteDesktop => "Layer 4 of 6 · Remote Desktop",
            FailureLayer.WindowsSignIn => "Layer 5 of 6 · Windows sign-in",
            _ => "Layer 6 of 6 · Tally",
        };
        DiagTitle.Text = d.Title;
        Explanation.Text = d.Explanation;
        Explanation.Visibility = d.Explanation.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        WhatToDo.Text = d.WhatToDo.Length > 0 ? d.WhatToDo : "Answer the question above.";
        Who.Text = d.WhoFixes.Length > 0 && d.WhoFixes != "—" ? "Who can fix it: " + d.WhoFixes : "";
    }

    private void Answer(bool yes)
    {
        if (_last?.NextQuestion is null) return;
        _answers = _last.NextQuestion switch
        {
            Troubleshooter.QRdp => _answers with { RdpWindowOpened = yes },
            Troubleshooter.QSignIn => _answers with { SignInWorked = yes },
            Troubleshooter.QTally => _answers with { TallyWorked = yes },
            _ => _answers,
        };
        Render();
    }

    private void Yes_Click(object sender, RoutedEventArgs e) => Answer(true);
    private void No_Click(object sender, RoutedEventArgs e) => Answer(false);
    private async void Restart_Click(object sender, RoutedEventArgs e) { _answers = new(); await _vm.RefreshAsync(force: true); Render(); }
    private void Diagnostics_Click(object sender, RoutedEventArgs e) => _vm.DiagnosticsCommand.Execute(null);
    private void Contact_Click(object sender, RoutedEventArgs e) => _vm.ContactSupport(this);
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
