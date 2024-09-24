#define FUSE_USE_VERSION 29
#include <errno.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>

static const char *content = "Hello, World!\n";

static int getattr_callback(const char *path, struct stat *stbuf) {
  puts("[+] getattr_callback");
  memset(stbuf, 0, sizeof(struct stat));

  /* マウント箇所からみたパスが"/file"かを確認 */
  if (strcmp(path, "/file") == 0) {
    stbuf->st_mode = S_IFREG | 0777; // 権限
    stbuf->st_nlink = 1; // ハードリンクの数
    stbuf->st_size = strlen(content); // ファイルサイズ
    return 0;
  }

  return -ENOENT;
}

static int open_callback(const char *path, struct fuse_file_info *fi) {
  puts("[+] open_callback");
  return 0;
}

static int read_callback(const char *path,
                         char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi) {
  puts("[+] read_callback");

  if (strcmp(path, "/file") == 0) {
    size_t len = strlen(content);
    if (offset >= len) return 0;

    /* データを返す */
    if ((size > len) || (offset + size > len)) {
      memcpy(buf, content + offset, len - offset);
      return len - offset;
    } else {
      memcpy(buf, content + offset, size);
      return size;
    }
  }

  return -ENOENT;
}

static struct fuse_operations fops = {
  .getattr = getattr_callback,
  .open = open_callback,
  .read = read_callback,
};

int main(int argc, char *argv[]) {
  return fuse_main(argc, argv, &fops, NULL);
}