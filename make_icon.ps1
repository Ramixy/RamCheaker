Add-Type -AssemblyName System.Drawing
$out = Join-Path $PSScriptRoot 'app.ico'
$sizes = 256,64,48,32,16
$pngs = @()
foreach ($s in $sizes) {
  $bmp = New-Object System.Drawing.Bitmap $s, $s
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'
  $k = $s / 64.0
  $path = New-Object System.Drawing.Drawing2D.GraphicsPath
  $r = 14 * $k; $d = $r * 2; $x = 2*$k; $y = 2*$k; $w = 60*$k
  $path.AddArc($x, $y, $d, $d, 180, 90); $path.AddArc($x+$w-$d, $y, $d, $d, 270, 90)
  $path.AddArc($x+$w-$d, $y+$w-$d, $d, $d, 0, 90); $path.AddArc($x, $y+$w-$d, $d, $d, 90, 90); $path.CloseFigure()
  $br = New-Object System.Drawing.Drawing2D.LinearGradientBrush (New-Object System.Drawing.Rectangle 0,0,$s,$s), ([System.Drawing.Color]::FromArgb(244,244,245)), ([System.Drawing.Color]::FromArgb(212,212,216)), 45
  $g.FillPath($br, $path)
  $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(12,12,13)), ([Math]::Max(1.5, 6*$k))
  $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
  $g.DrawEllipse($pen, 14*$k, 13*$k, 26*$k, 26*$k)
  $g.DrawLine($pen, 37*$k, 37*$k, 50*$k, 50*$k)
  $g.Dispose()
  $ms = New-Object System.IO.MemoryStream
  $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
  $pngs += ,($ms.ToArray())
}
$fs = [System.IO.File]::Create($out)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i=0; $i -lt $sizes.Count; $i++) {
  $s = $sizes[$i]; $b = if ($s -ge 256) {0} else {$s}
  $bw.Write([Byte]$b); $bw.Write([Byte]$b); $bw.Write([Byte]0); $bw.Write([Byte]0)
  $bw.Write([UInt16]1); $bw.Write([UInt16]32); $bw.Write([UInt32]$pngs[$i].Length); $bw.Write([UInt32]$offset)
  $offset += $pngs[$i].Length
}
foreach ($p in $pngs) { $bw.Write($p) }
$bw.Close()
Write-Output "icon ok"
