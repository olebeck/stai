#include "types.h"

namespace hooks {
  int init();
  int before_module_start(SceUID pid, SceUID modid);
  int after_module_unload(SceModuleCB& module_cb);
  int on_process_delete(SceUID pid);
};

