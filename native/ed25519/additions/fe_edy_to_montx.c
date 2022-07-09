
#include "fe.h"
#include "crypto_additions.h"

void fe_edy_to_montx(fe u, const fe y)
{
  /* 
     u = (y + 1) / (1 - y)

     NOTE: u=-1 is converted to y=0 since fe_invert is mod-exp
  */
  fe one, onepy, onemy;

  fe_1(one);
  fe_sub(onemy, one, y);
  fe_add(onepy, one, y);
  fe_invert(onemy, onemy);
  fe_mul(u, onepy, onemy);
}
