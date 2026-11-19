#include <tunables/global>
profile too-open flags=(complain) {
  file,
  /** rw,
  capability sys_admin,
  ptrace,
  /var/run/docker.sock rw,
}
