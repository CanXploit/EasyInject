namespace EasyInject;

public class ProcessInfo
{
    public int Pid { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Architecture { get; set; } = string.Empty;
    public string PidText => Pid.ToString();
}