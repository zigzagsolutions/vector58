using System.Diagnostics;
using BrowserSecurity.Agent.Shared.Ipc;

namespace BrowserSecurity.Agent.Tray;

/// <summary>
/// Notification-area icon showing protection status. It deliberately offers
/// no way to pause or disable protection: enforcement lives in the service
/// and the browser, and "Exit" only closes this status icon.
/// </summary>
internal sealed class TrayContext : ApplicationContext
{
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(15);
    private readonly NotifyIcon _icon;
    private readonly ContextMenuStrip _menu = new();
    private readonly ToolStripMenuItem _header = new("Browser Security") { Enabled = false };
    private readonly ToolStripMenuItem _syncNow = new("Check for policy updates");
    private readonly ToolStripMenuItem _openPortal = new("Open security portal");
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = (int)RefreshInterval.TotalMilliseconds };
    private readonly StatusClient _client = new();
    private readonly List<ToolStripItem> _statusLines = [];
    private TrayState? _lastState;
    private string? _portalUrl;

    public TrayContext()
    {
        _syncNow.Click += async (_, _) =>
        {
            var accepted = await _client.RequestSyncAsync();
            _icon!.ShowBalloonTip(3000, "Browser Security",
                accepted ? "Checking for policy updates." : "A check was requested recently. Please wait a moment.", ToolTipIcon.Info);
        };
        _openPortal.Click += (_, _) =>
        {
            if (_portalUrl is { } url && Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps)
                Process.Start(new ProcessStartInfo(u.ToString()) { UseShellExecute = true });
        };
        var exit = new ToolStripMenuItem("Close status icon (protection stays on)");
        exit.Click += (_, _) => ExitThread();

        _menu.Items.AddRange([_header, new ToolStripSeparator(), _syncNow, _openPortal, new ToolStripSeparator(), exit]);
        _icon = new NotifyIcon { ContextMenuStrip = _menu, Visible = true, Text = "Browser Security", Icon = SystemIcons.Shield };
        _icon.DoubleClick += (_, _) => ShowStatusBalloon();
        _timer.Tick += async (_, _) => await RefreshAsync();
        _timer.Start();
        _ = RefreshAsync();
    }

    private TrayView? _view;

    private async Task RefreshAsync()
    {
        var snapshot = await _client.GetStatusAsync();
        var view = TrayPresenter.Present(snapshot, DateTimeOffset.UtcNow);
        _view = view;
        _portalUrl = snapshot?.PortalUrl;
        _openPortal.Visible = _portalUrl is not null;
        _syncNow.Enabled = snapshot is not null;

        // NotifyIcon.Text is limited to 127 characters.
        _icon.Text = view.Tooltip.Length > 127 ? view.Tooltip[..127] : view.Tooltip;
        _icon.Icon = view.State switch
        {
            TrayState.Protected => SystemIcons.Shield,
            TrayState.Degraded => SystemIcons.Warning,
            _ => SystemIcons.Error,
        };

        foreach (var item in _statusLines) _menu.Items.Remove(item);
        _statusLines.Clear();
        var index = 1;
        foreach (var line in view.Lines)
        {
            var item = new ToolStripMenuItem(line) { Enabled = false };
            _menu.Items.Insert(index++, item);
            _statusLines.Add(item);
        }

        if (_lastState is not null && _lastState != view.State && view.State != TrayState.Protected) ShowStatusBalloon();
        _lastState = view.State;
    }

    private void ShowStatusBalloon()
    {
        if (_view is null) return;
        _icon.ShowBalloonTip(5000, _view.Tooltip, string.Join(Environment.NewLine, _view.Lines.Take(4)),
            _view.State == TrayState.Protected ? ToolTipIcon.Info : ToolTipIcon.Warning);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _timer.Dispose();
            _icon.Visible = false;
            _icon.Dispose();
            _menu.Dispose();
        }
        base.Dispose(disposing);
    }
}
