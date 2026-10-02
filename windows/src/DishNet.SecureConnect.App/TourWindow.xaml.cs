using System.Windows;
using System.Windows.Automation;
using System.Windows.Input;
using System.Windows.Media.Animation;

namespace DishNet.SecureConnect.App;

/// <summary>Three-step explanation. Pure XAML animation; honours Windows' "show animations" setting (reduced motion).</summary>
public partial class TourWindow : Window
{
    private static readonly (string Title, string Body)[] Steps =
    {
        ("Step 1 — Your office computer keeps everything",
         "Tally and your company data stay on the office computer or server, exactly where they are today. Nothing is copied to your laptop or to DishNet. For remote work the office computer must stay switched on, connected to the internet, and set up for Remote Desktop."),
        ("Step 2 — DishNet makes a private, encrypted connection",
         "DishNet Secure Connect links your laptop to the office through an encrypted tunnel. Only computers that DishNet has authorised for your business can use it. Click \"Connect to Office\" to open the tunnel; click \"Disconnect\" when you finish."),
        ("Step 3 — Remote Desktop shows you the office screen",
         "The connection alone does not show Tally. Open Windows Remote Desktop (the app offers a button), sign in with your Windows user name and password for the office computer, and you will see its desktop. Open Tally there as you normally do — it runs on the office computer; you only see and control it."),
    };

    private int _step;
    public bool Completed { get; private set; }

    public TourWindow()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            if (SystemParameters.ClientAreaAnimation && !SystemParameters.HighContrast)
                ((Storyboard)FindResource("TunnelFlow")).Begin(this, true);
            Show(0);
            NextBtn.Focus();
        };
        PreviewKeyDown += (_, e) =>
        {
            if (e.Key == Key.Right) { Next_Click(this, e); e.Handled = true; }
            else if (e.Key == Key.Left) { Back_Click(this, e); e.Handled = true; }
        };
    }

    private void Show(int i)
    {
        _step = Math.Clamp(i, 0, Steps.Length - 1);
        CaptionTitle.Text = Steps[_step].Title;
        CaptionBody.Text = Steps[_step].Body;
        StepCounter.Text = $"Step {_step + 1} of {Steps.Length} · about 2 minutes";
        Tab1.Style = (Style)FindResource(_step == 0 ? "StepActive" : "Step");
        Tab2.Style = (Style)FindResource(_step == 1 ? "StepActive" : "Step");
        Tab3.Style = (Style)FindResource(_step == 2 ? "StepActive" : "Step");
        // Emphasise the part of the picture the step talks about.
        OfficePc.StrokeThickness = _step == 0 ? 4 : 2;
        TunnelOuter.Opacity = _step == 1 ? 1 : 0.6;
        RemoteScreen.Opacity = _step == 2 ? 1 : 0.35;
        BackBtn.IsEnabled = _step > 0;
        NextBtn.Content = _step == Steps.Length - 1 ? "Set up my connection" : "Next";
        AutomationProperties.SetName(this, Steps[_step].Title);
    }

    private void Next_Click(object sender, RoutedEventArgs e)
    {
        if (_step < Steps.Length - 1) { Show(_step + 1); return; }
        Completed = true;
        DialogResult = true;
        Close();
    }

    private void Back_Click(object sender, RoutedEventArgs e) => Show(_step - 1);

    private void Skip_Click(object sender, RoutedEventArgs e)
    {
        Completed = false;
        DialogResult = false;
        Close();
    }
}
