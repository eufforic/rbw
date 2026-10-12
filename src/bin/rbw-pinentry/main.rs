//! A minimal pinentry for windows, which has no pinentry program of its own.
//! It speaks just enough of the assuan protocol for rbw-agent and asks for
//! the secret in an always-on-top windows forms dialog.

#[cfg(windows)]
const DIALOG: &str = r"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$form = New-Object Windows.Forms.Form
$form.Text = $env:RBW_PIN_TITLE
$form.TopMost = $true
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MinimizeBox = $false; $form.MaximizeBox = $false
$form.AutoSize = $true; $form.AutoSizeMode = 'GrowAndShrink'
$panel = New-Object Windows.Forms.FlowLayoutPanel
$panel.FlowDirection = 'TopDown'; $panel.AutoSize = $true; $panel.Padding = 12
$form.Controls.Add($panel)
foreach ($text in @($env:RBW_PIN_ERROR, $env:RBW_PIN_DESC)) {
    if (-not $text) { continue }
    $label = New-Object Windows.Forms.Label
    $label.Text = $text; $label.AutoSize = $true
    $label.MaximumSize = New-Object Drawing.Size(360, 0)
    if ($text -eq $env:RBW_PIN_ERROR) { $label.ForeColor = 'DarkRed' }
    $panel.Controls.Add($label)
}
$prompt = New-Object Windows.Forms.Label
$prompt.Text = $env:RBW_PIN_PROMPT; $prompt.AutoSize = $true
$panel.Controls.Add($prompt)
$box = New-Object Windows.Forms.TextBox
$box.Width = 360; $box.UseSystemPasswordChar = ($env:RBW_PIN_MASK -eq '1')
$panel.Controls.Add($box)
$ok = New-Object Windows.Forms.Button
$ok.Text = 'OK'; $ok.DialogResult = 'OK'
$panel.Controls.Add($ok)
$form.AcceptButton = $ok
$form.Add_Shown({ $form.Activate(); $box.Focus() })
if ($form.ShowDialog() -ne 'OK') { exit 1223 }
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
[Console]::Out.Write($box.Text)
";

/// Assuan escapes `%`, CR and LF in data lines and arguments.
fn percent_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '%' => "%25".to_string(),
            '\n' => "%0A".to_string(),
            '\r' => "%0D".to_string(),
            c => c.to_string(),
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Default)]
struct Request {
    title: String,
    desc: String,
    prompt: String,
    error: String,
}

/// The secret typed into the dialog, or None when the dialog was closed.
#[cfg(windows)]
fn ask(req: &Request) -> std::io::Result<Option<String>> {
    use std::os::windows::process::CommandExt as _;

    // codes are not secrets, and are easier to type when they are visible
    let mask = req.prompt.to_lowercase().contains("password");
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", DIALOG])
        // only the dialog should show, not a console behind it
        .creation_flags(rbw::windows::CREATE_NO_WINDOW)
        .env("RBW_PIN_TITLE", &req.title)
        .env("RBW_PIN_DESC", &req.desc)
        .env("RBW_PIN_PROMPT", &req.prompt)
        .env("RBW_PIN_ERROR", &req.error)
        .env("RBW_PIN_MASK", if mask { "1" } else { "0" })
        .stdin(std::process::Stdio::null())
        .output()?;
    if out.status.code() == Some(1223) {
        return Ok(None);
    }
    if !out.status.success() {
        return Err(std::io::Error::other(
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ));
    }
    Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
}

#[cfg(not(windows))]
fn ask(_req: &Request) -> std::io::Result<Option<String>> {
    Err(std::io::Error::other(
        "rbw-pinentry is only for windows; use a pinentry from your system",
    ))
}

fn serve(
    input: impl std::io::BufRead,
    mut output: impl std::io::Write,
    ask: impl Fn(&Request) -> std::io::Result<Option<String>>,
) -> std::io::Result<()> {
    let mut req = Request {
        title: "rbw".to_string(),
        ..Request::default()
    };
    writeln!(output, "OK Pleased to meet you")?;
    output.flush()?;
    for line in input.lines() {
        let line = line?;
        let (cmd, arg) = line.split_once(' ').unwrap_or((&line, ""));
        let arg = percent_decode(arg);
        match cmd {
            "SETTITLE" => req.title = arg,
            "SETDESC" => req.desc = arg,
            "SETPROMPT" => req.prompt = arg,
            "SETERROR" => req.error = arg,
            "GETPIN" => match ask(&req) {
                Ok(Some(pin)) => {
                    writeln!(output, "D {}", percent_encode(&pin))?;
                }
                Ok(None) => {
                    writeln!(output, "ERR 83886179 Operation cancelled")?;
                    output.flush()?;
                    continue;
                }
                Err(e) => {
                    writeln!(
                        output,
                        "ERR 83886082 {}",
                        percent_encode(&e.to_string())
                    )?;
                    output.flush()?;
                    continue;
                }
            },
            "BYE" => {
                writeln!(output, "OK closing connection")?;
                break;
            }
            _ => {}
        }
        writeln!(output, "OK")?;
        output.flush()?;
    }
    output.flush()
}

fn main() {
    let stdin = std::io::stdin();
    if let Err(e) = serve(stdin.lock(), std::io::stdout(), ask) {
        eprintln!("rbw-pinentry: {e}");
        std::process::exit(1);
    }
}

#[test]
fn test_serve_answers_getpin() {
    let input = b"SETTITLE rbw\nSETPROMPT Master Password\nSETDESC Unlock%0Anow\nGETPIN\n";
    let mut out = vec![];
    serve(&input[..], &mut out, |req| {
        assert_eq!(req.prompt, "Master Password");
        assert_eq!(req.desc, "Unlock\nnow");
        Ok(Some("pa%ss\nword".to_string()))
    })
    .unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "OK Pleased to meet you\nOK\nOK\nOK\nD pa%25ss%0Aword\nOK\n"
    );
}

#[test]
fn test_serve_reports_cancel() {
    let mut out = vec![];
    serve(&b"GETPIN\n"[..], &mut out, |_| Ok(None)).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "OK Pleased to meet you\nERR 83886179 Operation cancelled\n"
    );
}
