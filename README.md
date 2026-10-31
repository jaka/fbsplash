# fbsplash

Draws given image full-screen on framebuffer, waits for a keypress, and then returns back to where you were. It's meant for things like boot or kiosk splash screens, and it draws straight to the framebuffer without X or Wayland.

### Usage
```
./fbsplash image.ppm [0xRRGGBB]
```
Where RRGGBB is color in hex notation of pixels filling around.

### Compiling
```
apt-get install gcc libc6-dev make
```
