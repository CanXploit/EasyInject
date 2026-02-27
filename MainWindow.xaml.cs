using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;

namespace EasyInject;

public partial class MainWindow : Window
{

    private List<ProcessInfo> _allProcesses = [];
    private string? _selectedDllPath;

    private enum InjectMode { Dll, Shellcode, Assembly }
    private InjectMode _currentMode = InjectMode.Dll;

    private byte[]? _assembledBytes;

    public MainWindow()
    {
        InitializeComponent();
        RefreshProcesses();
        AppendLog("EasyInject ready. Select a process and injection mode.");
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        => DragMove();

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
    private void MinimizeButton_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Tab_Checked(object sender, RoutedEventArgs e)
    {

        if (PanelDll is null) return;

        if (sender == TabDll)
        {
            _currentMode = InjectMode.Dll;
            PanelDll.Visibility = Visibility.Visible;
            PanelShellcode.Visibility = Visibility.Collapsed;
            PanelAssembly.Visibility = Visibility.Collapsed;
            StatusModeText.Text = "MODE: DLL  •  LoadLibraryA";
        }
        else if (sender == TabShellcode)
        {
            _currentMode = InjectMode.Shellcode;
            PanelDll.Visibility = Visibility.Collapsed;
            PanelShellcode.Visibility = Visibility.Visible;
            PanelAssembly.Visibility = Visibility.Collapsed;
            StatusModeText.Text = "MODE: SHELLCODE  •  VirtualAllocEx + CreateRemoteThread";
        }
        else if (sender == TabAssembly)
        {
            _currentMode = InjectMode.Assembly;
            PanelDll.Visibility = Visibility.Collapsed;
            PanelShellcode.Visibility = Visibility.Collapsed;
            PanelAssembly.Visibility = Visibility.Visible;
            StatusModeText.Text = "MODE: ASSEMBLY  •  Assemble → Inject";
        }

        UpdateInjectButton();
    }

    private void RefreshProcesses_Click(object sender, RoutedEventArgs e) => RefreshProcesses();

    private void RefreshProcesses()
    {
        _allProcesses = Process.GetProcesses()
            .Select(p =>
            {
                string arch = "?";
                try { arch = Injector.GetProcessArchitecture(p.Id); } catch { }
                return new ProcessInfo { Pid = p.Id, Name = p.ProcessName, Architecture = arch };
            })
            .OrderBy(p => p.Name)
            .ToList();

        ApplyFilter(SearchBox.Text);
        AppendLog($"Found {_allProcesses.Count} processes.");
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        => ApplyFilter(SearchBox.Text);

    private void ApplyFilter(string query)
    {
        var filtered = string.IsNullOrWhiteSpace(query)
            ? _allProcesses
            : _allProcesses.Where(p =>
                p.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                p.Pid.ToString().Contains(query)).ToList();

        ProcessListBox.ItemsSource = filtered;
        ProcessCountText.Text = $" [{filtered.Count}]";
    }

    private void ProcessListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        SelectedProcessText.Text = ProcessListBox.SelectedItem is ProcessInfo proc
            ? $"{proc.Name}  (PID: {proc.Pid})  [{proc.Architecture}]"
            : "none selected";
        UpdateInjectButton();
    }

    private void DllPathBox_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) &&
                    ((string[])e.Data.GetData(DataFormats.FileDrop))
                        .Any(f => f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    private void DllPathBox_Drop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        var files = (string[])e.Data.GetData(DataFormats.FileDrop);
        string? dll = files.FirstOrDefault(f => f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase));
        if (dll is null) { AppendLog("✘ Dropped file is not a DLL.", error: true); return; }
        LoadDll(dll);
    }

    private void BrowseDll_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Select DLL to Inject",
            Filter = "Dynamic Link Library (*.dll)|*.dll|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog() == true) LoadDll(dlg.FileName);
    }

    private void LoadDll(string path)
    {
        _selectedDllPath = path;
        DllPathBox.Text = path;
        DllFileNameText.Text = Path.GetFileName(path);

        var info = new FileInfo(path);
        DllSizeText.Text = info.Length < 1024 * 1024
            ? $"{info.Length / 1024.0:F1} KB"
            : $"{info.Length / (1024.0 * 1024):F2} MB";

        string arch = Injector.GetDllArchitecture(path);
        DllArchText.Text = arch;

        AppendLog($"DLL loaded: {Path.GetFileName(path)}  [{arch}]  {DllSizeText.Text}");
        UpdateInjectButton();
    }

    private void ShellcodeFileBox_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void ShellcodeFileBox_Drop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        string? file = ((string[])e.Data.GetData(DataFormats.FileDrop)).FirstOrDefault();
        if (file is not null) LoadShellcodeFile(file);
    }

    private void BrowseShellcodeFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Select raw shellcode binary",
            Filter = "Binary files (*.bin;*.sc;*.raw)|*.bin;*.sc;*.raw|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog() == true) LoadShellcodeFile(dlg.FileName);
    }

    private void LoadShellcodeFile(string path)
    {
        try
        {
            byte[] bytes = File.ReadAllBytes(path);

            ShellcodeHexBox.Text = BitConverter.ToString(bytes).Replace("-", " ");
            ShellcodeFileBox.Text = path;
            AppendLog($"Shellcode file loaded: {Path.GetFileName(path)}  ({bytes.Length} bytes)");
        }
        catch (Exception ex)
        {
            AppendLog($"✘ Failed to read file: {ex.Message}", error: true);
        }
    }

    private void ClearShellcode_Click(object sender, RoutedEventArgs e)
    {
        ShellcodeHexBox.Text = string.Empty;
        ShellcodeFileBox.Text = string.Empty;
        AppendLog("Shellcode cleared.");
        UpdateInjectButton();
    }

    private void ShellcodeHexBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        int count = 0;
        try { count = ShellcodeParser.Parse(ShellcodeHexBox.Text).Length; } catch { }
        ShellcodeBytesText.Text = count.ToString();
        UpdateInjectButton();
    }

    private void BrowseAsmFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Select assembly source file",
            Filter = "ASM files (*.asm;*.s;*.nasm)|*.asm;*.s;*.nasm|Text files (*.txt)|*.txt|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            AsmCodeBox.Text = File.ReadAllText(dlg.FileName);
            AppendLog($"ASM file loaded: {Path.GetFileName(dlg.FileName)}");
        }
        catch (Exception ex)
        {
            AppendLog($"✘ Failed to read file: {ex.Message}", error: true);
        }
    }

    private void AssemblePreview_Click(object sender, RoutedEventArgs e)
    {
        bool is64 = (AsmArchCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() == "x64";
        var result = MiniAssembler.Assemble(AsmCodeBox.Text, is64);

        if (!result.Success)
        {
            AsmBytesText.Text = $"ERROR: {result.ErrorMessage}";
            AsmBytesText.Foreground = (SolidColorBrush)FindResource("AccentRedBrush");
            _assembledBytes = null;
            AppendLog($"✘ Assembler: {result.ErrorMessage}", error: true);
        }
        else
        {
            _assembledBytes = result.Bytes;
            string hex = BitConverter.ToString(_assembledBytes).Replace("-", " ");
            AsmBytesText.Text = $"{_assembledBytes.Length} bytes  →  {hex}";
            AsmBytesText.Foreground = (SolidColorBrush)FindResource("AccentGreenBrush");
            AppendLog($"✔ Assembled {_assembledBytes.Length} bytes.", success: true);
        }

        UpdateInjectButton();
    }

    private void InjectButton_Click(object sender, RoutedEventArgs e)
    {
        if (ProcessListBox.SelectedItem is not ProcessInfo proc) return;

        SetStatus("Injecting…", Brushes.Yellow);

        switch (_currentMode)
        {
            case InjectMode.Dll:
                InjectDll(proc);
                break;

            case InjectMode.Shellcode:
                InjectShellcode(proc);
                break;

            case InjectMode.Assembly:
                InjectAssemblyBytes(proc);
                break;
        }
    }

    private void InjectDll(ProcessInfo proc)
    {
        if (_selectedDllPath is null) return;
        AppendLog($"▶ DLL inject → {proc.Name} (PID: {proc.Pid})");
        try
        {
            var r = Injector.Inject(proc.Pid, _selectedDllPath);
            HandleResult(r);
        }
        catch (Exception ex) { HandleException(ex); }
    }

    private void InjectShellcode(ProcessInfo proc)
    {
        byte[] bytes;
        try { bytes = ShellcodeParser.Parse(ShellcodeHexBox.Text); }
        catch (Exception ex) { AppendLog($"✘ Parse error: {ex.Message}", error: true); return; }

        if (bytes.Length == 0) { AppendLog("✘ No shellcode bytes to inject.", error: true); return; }

        AppendLog($"▶ Shellcode inject → {proc.Name} (PID: {proc.Pid})  [{bytes.Length} bytes]");
        try
        {
            var r = Injector.InjectShellcode(proc.Pid, bytes);
            HandleResult(r);
        }
        catch (Exception ex) { HandleException(ex); }
    }

    private void InjectAssemblyBytes(ProcessInfo proc)
    {
        if (_assembledBytes is null || _assembledBytes.Length == 0)
        {
            AppendLog("✘ No assembled bytes — click ▶ ASSEMBLE first.", error: true);
            return;
        }

        AppendLog($"▶ ASM inject → {proc.Name} (PID: {proc.Pid})  [{_assembledBytes.Length} bytes]");
        try
        {
            var r = Injector.InjectShellcode(proc.Pid, _assembledBytes);
            HandleResult(r);
        }
        catch (Exception ex) { HandleException(ex); }
    }

    private void HandleResult(InjectionResult r)
    {
        if (r.IsSuccess)
        {
            AppendLog($"✔ {r.Message}", success: true);
            SetStatus("Injection successful", (SolidColorBrush)FindResource("AccentGreenBrush"));
        }
        else
        {
            AppendLog($"✘ {r.Message}", error: true);
            SetStatus("Injection failed", (SolidColorBrush)FindResource("AccentRedBrush"));
        }
    }

    private void HandleException(Exception ex)
    {
        AppendLog($"✘ Exception: {ex.Message}", error: true);
        SetStatus("Error", (SolidColorBrush)FindResource("AccentRedBrush"));
    }

    private void UpdateInjectButton()
    {
        bool processOk = ProcessListBox.SelectedItem is ProcessInfo;
        bool payloadOk = _currentMode switch
        {
            InjectMode.Dll => _selectedDllPath is not null && File.Exists(_selectedDllPath),
            InjectMode.Shellcode => ShellcodeHexBox?.Text?.Trim().Length > 0,
            InjectMode.Assembly => _assembledBytes is { Length: > 0 },
            _ => false
        };

        InjectButton.IsEnabled = processOk && payloadOk;
    }

    private void AppendLog(string message, bool success = false, bool error = false)
    {
        string timestamp = DateTime.Now.ToString("HH:mm:ss");
        string line = $"[{timestamp}] {message}\n";

        var color = success ? (SolidColorBrush)FindResource("AccentGreenBrush")
                  : error ? (SolidColorBrush)FindResource("AccentRedBrush")
                  : (SolidColorBrush)FindResource("TextSecondaryBrush");

        LogTextBlock.Text += line;
        LogTextBlock.Foreground = color;
        LogScrollViewer.ScrollToBottom();
    }

    private void SetStatus(string text, SolidColorBrush color)
    {
        StatusText.Text = text;
        StatusText.Foreground = color;
        StatusDot.Fill = color;
    }
}