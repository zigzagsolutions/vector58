namespace BrowserSecurity.Agent.Tray;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        // One tray per signed-in user session.
        using var mutex = new Mutex(initiallyOwned: true, @"Local\Vector58.BrowserSecurity.Tray", out var created);
        if (!created) return;
        ApplicationConfiguration.Initialize();
        Application.Run(new TrayContext());
    }
}
