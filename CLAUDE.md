
## Running GUI apps

A TigerVNC server (XFCE desktop) runs on display `:1`, served on `127.0.0.1:5901` (localhost-only, 1280x800, 24-bit).

- The shell has no `DISPLAY` set by default. Launch GUI apps with `DISPLAY=:1`, e.g. `DISPLAY=:1 xclock &`.
- Screenshot the display to verify rendering: `DISPLAY=:1 import -window root screen.png` (ImageMagick), or `xwd -root -out screen.xwd`.
- List mapped windows: `DISPLAY=:1 xwininfo -root -children`.
- Port 5901 is localhost-only. To view remotely, tunnel it: `ssh -L 5901:localhost:5901 <host>`, then point a VNC viewer at `localhost:5901`.
