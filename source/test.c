#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void open_cmd(const char* command) {
  char final_command[256];

  snprintf(final_command, sizeof(final_command), "start %s", command);

  printf("Running command: %s\n", final_command);

  system(final_command);
}
