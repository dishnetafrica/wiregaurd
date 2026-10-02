using System.Windows;
using System.Windows.Controls;
using DishNet.SecureConnect.Core.Onboarding;

namespace DishNet.SecureConnect.App;

public partial class HelpWindow : Window
{
    private readonly MainViewModel _vm;

    public HelpWindow(MainViewModel vm, string? openTopic = null)
    {
        InitializeComponent();
        _vm = vm;
        SupportLine.Text = vm.SupportContact.Length > 0 ? "Contact DishNet: " + vm.SupportContact : "Contact DishNet support from the main screen.";
        ContactBody.Text = vm.SupportContact.Length > 0
            ? $"DishNet support: {vm.SupportContact}. Tell us your business name and what the app shows. Never send passwords."
            : "Tell DishNet your business name and what the app shows. Never send passwords.";
        Topics.ItemsSource = HelpTopics.All;
        var start = openTopic is null ? null : HelpTopics.Find(openTopic);
        Topics.SelectedItem = start ?? HelpTopics.All.FirstOrDefault();
        Topics.Focus();
    }

    private void Topics_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Topics.SelectedItem is not HelpTopic t) return;
        TopicTitle.Text = t.Title;
        TopicBody.Text = HelpTopics.ToPlainText(t.Body);
    }

    private void Tour_Click(object sender, RoutedEventArgs e) => _vm.ShowTour(this);
    private void Diagnostics_Click(object sender, RoutedEventArgs e) => _vm.DiagnosticsCommand.Execute(null);
    private void Contact_Click(object sender, RoutedEventArgs e) => _vm.ContactSupport(this);
}
