#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/sys.h"

u32_t 
sys_now()
{
  return 114514;
}


// SYS_LIGHTWEIGHT_PROT
/*
sys_prot_t
sys_arch_protect(void)
{
  return 0;
}

void
sys_arch_unprotect(sys_prot_t pval)
{

}*/