# Renders the installer artwork in packaging/windows/art from the dashboard logo.
# Run it again after changing the logo; the PNG/ICO output is committed so a
# normal build does not need to run this. Colours are the dashboard's tokens.
param([string]$Logo = "$PSScriptRoot\..\..\dashboard\public\assets\lighthouse-logo.png",
      [string]$Out = "$PSScriptRoot\art")
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
New-Item -ItemType Directory -Force $Out | Out-Null

$green = [Drawing.Color]::FromArgb(0x2A, 0x96, 0x79)    # --green
$tagline = [Drawing.Color]::FromArgb(0xD8, 0xF3, 0xE9)  # .login > p
$quiet = [Drawing.Color]::FromArgb(0xCD, 0xEE, 0xE2)    # .login .eyebrow
$logoImage = [Drawing.Image]::FromFile((Resolve-Path $Logo).Path)

function New-Canvas([int]$Width, [int]$Height) {
    $bitmap = New-Object Drawing.Bitmap $Width, $Height, ([Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = 'AntiAlias'
    $graphics.InterpolationMode = 'HighQualityBicubic'
    $graphics.PixelOffsetMode = 'HighQuality'
    $graphics.TextRenderingHint = 'AntiAliasGridFit'
    return @($bitmap, $graphics)
}

# The dashboard's brand mark: the logo on a white disc (.login img, .brand img).
function Draw-Mark($Graphics, [single]$X, [single]$Y, [single]$Size) {
    $Graphics.FillEllipse([Drawing.Brushes]::White, $X, $Y, $Size, $Size)
    $inset = $Size * 0.05
    $clip = New-Object Drawing.Drawing2D.GraphicsPath
    $clip.AddEllipse($X + $inset, $Y + $inset, $Size - 2 * $inset, $Size - 2 * $inset)
    $Graphics.SetClip($clip)
    $Graphics.DrawImage($logoImage, $X + $inset, $Y + $inset, $Size - 2 * $inset, $Size - 2 * $inset)
    $Graphics.ResetClip()
}

function New-Font([string[]]$Families, [single]$Pixels, [Drawing.FontStyle]$Style) {
    foreach ($family in $Families) {
        $font = New-Object Drawing.Font $family, $Pixels, $Style, ([Drawing.GraphicsUnit]::Pixel)
        if ($font.Name -eq $family) { return $font }
        $font.Dispose()
    }
    throw "None of these fonts is installed: $($Families -join ', ')"
}

function Draw-Centered($Graphics, [string]$Text, $Font, [Drawing.Color]$Color, [single]$Top, [single]$Width) {
    $format = New-Object Drawing.StringFormat
    $format.Alignment = 'Center'
    $brush = New-Object Drawing.SolidBrush $Color
    $Graphics.DrawString($Text, $Font, $brush, (New-Object Drawing.RectangleF 0, $Top, $Width, 400), $format)
}

# Every Windows display scale gets its own exact-size image, so Setup never has to
# resize one (a resized full-bleed mark lands a pixel off centre).
$scales = 1, 1.25, 1.5, 1.75, 2

# Welcome/finish page panel. 164x314 is Inno's 100% size.
foreach ($scale in $scales) {
    $w, $h = [int][math]::Round(164 * $scale), [int][math]::Round(314 * $scale)
    $bitmap, $g = New-Canvas $w $h
    $g.Clear($green)
    # Whole pixels, and the same margin on both sides.
    $mark = [int][math]::Round(100 * $scale)
    if (($w - $mark) % 2) { $mark-- }
    Draw-Mark $g (($w - $mark) / 2) ([math]::Round(44 * $scale)) $mark
    # Uppercase extra-bold, like the dashboard's h1.
    $title = New-Font @('Segoe UI Black', 'Segoe UI') (19 * $scale) ([Drawing.FontStyle]::Bold)
    Draw-Centered $g 'LIGHTHOUSE' $title ([Drawing.Color]::White) (160 * $scale) $w
    $small = New-Font @('Segoe UI') (11.5 * $scale) ([Drawing.FontStyle]::Regular)
    Draw-Centered $g "Guiding you to`nsafer shores" $small $tagline (190 * $scale) $w
    $eyebrow = New-Font @('Segoe UI Semibold', 'Segoe UI') (9.5 * $scale) ([Drawing.FontStyle]::Regular)
    # [char] rather than a literal: Windows PowerShell reads this file as ANSI.
    $dot = [char]0x00B7
    Draw-Centered $g "PRIVATE  $dot  ON THIS PC" $eyebrow $quiet (276 * $scale) $w
    $bitmap.Save("$Out\wizard-$($scale * 100).png", [Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bitmap.Dispose()
}

# Header mark on the green page header. 55x55 at 100%.
foreach ($scale in $scales) {
    $size = [int][math]::Round(55 * $scale)
    $inset = [int][math]::Round(2 * $scale)
    $bitmap, $g = New-Canvas $size $size
    $g.Clear([Drawing.Color]::Transparent)
    Draw-Mark $g $inset $inset ($size - 2 * $inset)
    $bitmap.Save("$Out\header-$($scale * 100).png", [Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bitmap.Dispose()
}

# Icon for Setup, the shortcuts and Apps & features. Small sizes as 32-bit DIBs
# (what every consumer of .ico reads), 256 as PNG (the Vista+ convention). Every
# size the taskbar, title bar and Explorer ask for at 100-200% scaling is present,
# so Windows never scales a neighbouring size (taskbar: 24/30/36/48).
$entries = foreach ($size in 16, 20, 24, 30, 32, 36, 40, 48, 64, 96, 128, 256) {
    $bitmap, $g = New-Canvas $size $size
    $g.Clear([Drawing.Color]::Transparent)
    Draw-Mark $g 0 0 $size
    $g.Dispose()
    if ($size -eq 256) {
        $stream = New-Object IO.MemoryStream
        $bitmap.Save($stream, [Drawing.Imaging.ImageFormat]::Png)
        $data = $stream.ToArray()
    } else {
        $rect = New-Object Drawing.Rectangle 0, 0, $size, $size
        $locked = $bitmap.LockBits($rect, 'ReadOnly', ([Drawing.Imaging.PixelFormat]::Format32bppArgb))
        $pixels = New-Object byte[] ($size * $size * 4)
        [Runtime.InteropServices.Marshal]::Copy($locked.Scan0, $pixels, 0, $pixels.Length)
        $bitmap.UnlockBits($locked)
        $maskRow = [int]([math]::Ceiling($size / 32) * 4)
        $stream = New-Object IO.MemoryStream
        $writer = New-Object IO.BinaryWriter $stream
        # BITMAPINFOHEADER; height counts the colour rows plus the AND-mask rows.
        $writer.Write([int]40); $writer.Write([int]$size); $writer.Write([int]($size * 2))
        $writer.Write([int16]1); $writer.Write([int16]32); $writer.Write([int]0)
        $writer.Write([int]($pixels.Length + $maskRow * $size)); $writer.Write([int]0); $writer.Write([int]0)
        $writer.Write([int]0); $writer.Write([int]0)
        # DIB rows are stored bottom-up.
        for ($row = $size - 1; $row -ge 0; $row--) { $writer.Write($pixels, $row * $size * 4, $size * 4) }
        $writer.Write((New-Object byte[] ($maskRow * $size)))
        $writer.Flush()
        $data = $stream.ToArray()
    }
    $bitmap.Dispose()
    [pscustomobject]@{ Size = $size; Data = $data }
}
$file = New-Object IO.MemoryStream
$writer = New-Object IO.BinaryWriter $file
$writer.Write([int16]0); $writer.Write([int16]1); $writer.Write([int16]$entries.Count)
$offset = 6 + 16 * $entries.Count
foreach ($entry in $entries) {
    $dimension = if ($entry.Size -ge 256) { 0 } else { $entry.Size }
    $writer.Write([byte]$dimension); $writer.Write([byte]$dimension); $writer.Write([byte]0); $writer.Write([byte]0)
    $writer.Write([int16]1); $writer.Write([int16]32); $writer.Write([int]$entry.Data.Length); $writer.Write([int]$offset)
    $offset += $entry.Data.Length
}
foreach ($entry in $entries) { $writer.Write($entry.Data) }
$writer.Flush()
[IO.File]::WriteAllBytes("$Out\lighthouse.ico", $file.ToArray())

# Dashboard app icons (web app manifest and favicon): what Edge and Chrome show for
# LightHouse's own window and taskbar entry.
$assets = "$PSScriptRoot\..\..\dashboard\public\assets"
foreach ($size in 192, 512) {
    $bitmap, $g = New-Canvas $size $size
    $g.Clear([Drawing.Color]::Transparent)
    Draw-Mark $g 0 0 $size
    $bitmap.Save("$assets\app-icon-$size.png", [Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bitmap.Dispose()
}
$logoImage.Dispose()
Get-ChildItem $Out | Select-Object Name, Length
