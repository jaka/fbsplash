#include <linux/fb.h>
#include <linux/vt.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <termios.h>

struct globals {
	unsigned char *addr;
	struct fb_var_screeninfo scr_var;
	struct fb_fix_screeninfo scr_fix;
  unsigned bytes_per_pixel;
} G;

static char *strchrnul(char *s, char a)
{
  char *p;
  p = s;
  while (*p != 0 && *p != a) {
    p++;
  }
  return p;
}

static int fb_open(const char *fb_device)
{
  int fbfd;
  int rv;

  fbfd = open(fb_device, O_RDWR);
  if (fbfd < 0) {
    fprintf(stderr, "Cannot open framebuffer device!\n");
    return -1;
  }

  ioctl(fbfd, FBIOGET_VSCREENINFO, &G.scr_var);
  ioctl(fbfd, FBIOGET_FSCREENINFO, &G.scr_fix);

  G.bytes_per_pixel = (G.scr_var.bits_per_pixel + 7) >> 3;
  if (G.bytes_per_pixel != 4) {
    fprintf(stderr, "Supporting only modes with 4 bytes per pixel!\n");
    close(fbfd);
    return -1;
  }

  rv = -1;
  G.addr = mmap(NULL,
      (G.scr_var.yres_virtual ? G.scr_var.yres_virtual : G.scr_var.yres) * G.scr_fix.line_length,
      PROT_WRITE, MAP_SHARED, fbfd, 0);
  if (G.addr != MAP_FAILED) {
    rv = 0;
    G.addr += G.scr_var.yoffset * G.scr_fix.line_length + G.scr_var.xoffset * G.bytes_per_pixel;
  }

  close(fbfd);
  return rv;
}

static unsigned fb_pixel_value(unsigned r, unsigned g, unsigned b)
{
  return b + (g << 8) + (r << 16);
}

static void fb_write_pixel(unsigned char *addr, unsigned pixel)
{
  addr[0] = pixel;
  addr[1] = pixel >> 8;
  addr[2] = pixel >> 16;
}

static void fb_drawfullrectangle(
  unsigned int nx1pos, unsigned int ny1pos, unsigned int nx2pos, unsigned int ny2pos,
  unsigned char nred, unsigned char ngreen, unsigned char nblue)
{
  unsigned int xcnt, ycnt, xpos, ypos;
  unsigned int thispix;
  unsigned char *ptr;

  thispix = fb_pixel_value(nred, ngreen, nblue);

  xpos = nx1pos;
  ypos = ny1pos;
  ycnt = ny2pos - ny1pos;
  do {

    ptr = G.addr + ypos * G.scr_fix.line_length + xpos * G.bytes_per_pixel;
    ypos++;

    xcnt = nx2pos - nx1pos;
    do {
      fb_write_pixel(ptr, thispix);
      ptr += G.bytes_per_pixel;
    } while (--xcnt);

  } while (--ycnt);

}

static void fb_drawimage(char *filename, int center)
{
  char header[80];
  int rem;
  char *p;
  unsigned int width, height, line_size, max_color_val;

  unsigned char *pixline;
  unsigned int i, j;
  unsigned int xpos, ypos;
  unsigned int thispix;
  unsigned char *ptr, *s;

  FILE *file;
  file = fopen(filename, "r");
  if (!file) {
    return;
  }

  /* Parse ppm header:
   * - Magic: two characters "P6".
   * - Whitespace (blanks, TABs, CRs, LFs).
   * - A width, formatted as ASCII characters in decimal.
   * - Whitespace.
   * - A height, ASCII decimal.
   * - Whitespace.
   * - The maximum color value, ASCII decimal, in 0..65535
   * - Newline or other single whitespace character.
   *   (we support newline only)
   * - A raster of Width * Height pixels in triplets of rgb
   *   in pure binary by 1 or 2 bytes. (we support only 1 byte)
   */

  width = 0;
  height = 0;

  p = header;
  rem = sizeof(header);
  while (!feof(file)) {
    if (fgets(p, rem, file) == NULL) {
      fclose(file);
      return;
    }
    p = strchrnul(p, '#');
    *p = 0;
    if (sscanf(header, "P6 %u %u %u", &width, &height, &max_color_val) == 3) {
      break;
    }
  }

  if (width == 0 || height == 0 || max_color_val > 255) {
    fprintf(stderr, "Not a valid PPM file!\n");
    fclose(file);
    return;
  }

  if (width > G.scr_var.xres) {
    width = G.scr_var.xres;
  }
  if (height > G.scr_var.yres) {
    height = G.scr_var.yres;
  }
  if (center) {
    xpos = (G.scr_var.xres - width) / 2;
    ypos = (G.scr_var.yres - height) / 2;
  }
  else {
    xpos = 0;
    ypos = 0;
  }

  line_size = 3 * width;
  pixline = malloc(line_size);

  for (j = 0; j < height; j++) {

    if (fread(pixline, 1, line_size, file) != line_size) {
      fprintf(stderr, "Bad PPM file!");
      break;
    }

    s = pixline;
    ptr = G.addr + (ypos + j) * G.scr_fix.line_length + xpos * G.bytes_per_pixel;
    for (i = 0; i < width; i++) {
      thispix = fb_pixel_value(s[0], s[1], s[2]);
      fb_write_pixel(ptr, thispix);
      ptr += G.bytes_per_pixel;
      s += 3;
    }
  }

  free(pixline);
  fclose(file);
}


static char keypress(void)
{
  char c;
  struct termios oldt, newt;

  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~(ICANON | ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  read(STDIN_FILENO, &c, 1);

  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

  return c;
}

#define ESC "\033"

static int get_vt_fd(void)
{
  int fd;
  int rv;
  struct vt_stat vtstat;

  for (fd = 0; fd < 3; fd++) {
    rv = ioctl(fd, VT_GETSTATE, &vtstat);
    if (!rv) {
      return fd;
    }
  }

  fd = open("/dev/console", O_RDONLY | O_NONBLOCK);
  if (fd < 0) {
    return -1;
  }
  rv = ioctl(fd, VT_GETSTATE, &vtstat);

  if (!rv) {
    return fd;
  }
  return -1;
}

static unsigned short find_free_vtno(void)
{
  int vtno;
  int fd;
  int rv;

  fd = get_vt_fd();
  if (fd < 0) {
    return 0;
  }

  rv = ioctl(fd, VT_OPENQRY, &vtno);
  if (fd > 2) {
    close(fd);
  }
  if (rv || vtno <= 0) {
    return 0;
  }

  return vtno;
}

static void signal_handler(int signum)
{
  if (signum == SIGTERM) {
    signal(SIGTERM, SIG_IGN);
  }
}

#define VTNAME "/dev/tty"
#define VT_POINTER(x) ((void *)(unsigned long)x)

int main(int argc, char **argv)
{
  char *filename;
  unsigned int color;

  int pid;
  struct sigaction sa;

  int fd;
  unsigned short old_vtno;
  unsigned short vtno;
  char vtname[sizeof(VTNAME) + 6];

  struct vt_stat vtstat;
  int rv;

  if (argc < 2) {
    printf("%s [filename] [hexcolor]\n", argv[0]);
    return 0;
  }
  filename = argv[1];

  color = 0x90c048;
  if (argc > 2) {
    if (sscanf(argv[2], "0x%x", &color) != 1) {
      return 0;
    }
  }

  if (fb_open("/dev/fb0") < 0) {
    return 1;
  }

  vtno = find_free_vtno();
  if (!vtno) {
    fprintf(stderr, "Cannot find free VT!\n");
    return 1;
  }

  pid = fork();
  if (pid) {
    printf("%d\n", pid);
    return 0;
  }

  sa.sa_flags = 0;
  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGTERM, &sa, NULL) < 0) {
    fprintf(stderr, "Signal handler could not be set!\n");
    return 1;
  }

  close(STDIN_FILENO);

  sprintf(vtname, VTNAME "%hu", vtno);
  fd = open(vtname, O_RDWR);
  if (fd < 0) {
    return 1;
  }

  if (fd != 0) {
    dup2(fd, STDIN_FILENO);
  }

  rv = ioctl(STDIN_FILENO, VT_GETSTATE, &vtstat);
  old_vtno = !rv ? vtstat.v_active : 0;

  ioctl(fd, VT_ACTIVATE, VT_POINTER(vtno));
  ioctl(fd, VT_WAITACTIVE, VT_POINTER(vtno));

  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);

  write(STDOUT_FILENO, ESC"[?25l", 6);

  fb_drawfullrectangle(0, 0, G.scr_var.xres, G.scr_var.yres, color >> 16, color >> 8, color);
  fb_drawimage(filename, 1);

  keypress();

  write(STDOUT_FILENO, ESC"[?25h", 6);

  if (old_vtno) {
    ioctl(fd, VT_ACTIVATE, VT_POINTER(old_vtno));
    ioctl(fd, VT_WAITACTIVE, VT_POINTER(old_vtno));
  }

  close(fd);

  ioctl(STDIN_FILENO, VT_DISALLOCATE, VT_POINTER(vtno));

  return 0;
}
