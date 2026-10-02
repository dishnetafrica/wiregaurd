using System.Windows;

namespace DishNet.SecureConnect.App;

public partial class MainWindow : Window
{
    public MainWindow() { InitializeComponent(); }

    private MainViewModel Vm => (MainViewModel)DataContext;
    private void HowItWorks_Click(object sender, RoutedEventArgs e) => Vm.ShowTour(this);
    private void Help_Click(object sender, RoutedEventArgs e) => Vm.ShowHelp(this);
    private void Contact_Click(object sender, RoutedEventArgs e) => Vm.ContactSupport(this);
    private void TallySetup_Click(object sender, RoutedEventArgs e) => Vm.ShowTallySetup(this);
    private void Trouble_Click(object sender, RoutedEventArgs e) => Vm.ShowTroubleshooter(this);
    private void DeclineGateway_Click(object sender, RoutedEventArgs e) => Vm.DeclineGateway();
}
