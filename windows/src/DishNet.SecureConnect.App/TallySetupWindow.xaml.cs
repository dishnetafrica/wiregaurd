using System.Windows;
using System.Windows.Controls;
using DishNet.SecureConnect.Core.Onboarding;

namespace DishNet.SecureConnect.App;

/// <summary>Guided "Set up Tally remote access" journey with a practice run. All step logic lives in Core.TallyJourney (tested).</summary>
public partial class TallySetupWindow : Window
{
    public sealed record Row(int Number, JourneyStep Step, bool IsCurrent, bool CanConfirm)
    {
        public bool HasAction => IsCurrent && Step.Action is TallyJourney.ActionConnect or TallyJourney.ActionOpenRdp or TallyJourney.ActionDisconnect;
        public string ActionLabel => Step.Action switch
        {
            TallyJourney.ActionConnect => "Connect to Office",
            TallyJourney.ActionOpenRdp => "Open Remote Desktop",
            TallyJourney.ActionDisconnect => "Disconnect",
            _ => "",
        };
        public string ConfirmLabel => Step.Key switch
        {
            TallyJourney.KeyOpenRdp => "✔ Remote Desktop opened",
            TallyJourney.KeySignIn => "✔ I signed in",
            TallyJourney.KeyOpenCompany => "✔ Tally company is open",
            TallyJourney.KeyTask => "✔ Task done",
            TallyJourney.KeyDisconnect => "✔ I disconnected properly",
            _ => "✔ Done",
        };
        public string SourceLabel => Step.Status switch
        {
            StepStatus.Verified => "Checked by the software",
            StepStatus.Confirmed => "Confirmed by you",
            StepStatus.Attention => "Needs attention",
            _ => Step.Action is TallyJourney.ActionConfirm or TallyJourney.ActionOpenRdp or TallyJourney.ActionDisconnect ? "You confirm this step" : "Checked automatically",
        };
    }

    private readonly MainViewModel _vm;

    public TallySetupWindow(MainViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        _vm.PropertyChanged += (_, e) => { if (e.PropertyName is nameof(MainViewModel.JourneyVersion)) Dispatcher.Invoke(Render); };
        Render();
    }

    private void Render()
    {
        var steps = _vm.JourneySteps;
        var cur = TallyJourney.Current(steps);
        var rows = steps.Select((s, i) => new Row(i + 1, s, cur is not null && s.Key == cur.Key, TallyJourney.CanConfirm(steps, s.Key))).ToList();
        Steps.ItemsSource = rows;
        var done = steps.Count(s => s.IsDone);
        ProgressText.Text = $"{done} of {steps.Count} steps done";
        DoneBanner.Visibility = TallyJourney.AllDone(steps) ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void Action_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not Row r) return;
        await _vm.RunJourneyActionAsync(r.Step.Action);
    }

    private async void Confirm_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not Row r) return;
        await _vm.ConfirmJourneyStepAsync(r.Step.Key);
    }

    private async void Practice_Click(object sender, RoutedEventArgs e) => await _vm.ResetPracticeAsync();
    private void Trouble_Click(object sender, RoutedEventArgs e) => _vm.ShowTroubleshooter(this);
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
