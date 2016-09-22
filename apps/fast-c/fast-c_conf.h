#ifndef __FAST_C_CONF_H__
#define __FAST_C_CONF_H__

#ifdef FAST_C_CONF_EB_SEPERATE
#define FAST_C_EB_SEPERATE                     FAST_C_CONF_EB_SEPERATE
#else /* FAST_C_CONF_EB_SEPERATE */
#define FAST_C_EB_SEPERATE                     1
#endif /* FAST_C_CONF_EB_SEPERATE */


#define FAST_C_EB_PERIOD            76

#define FAST_C_COMMON_PERIOD            31

#define FAST_C_CONVERGECAST_PERIOD                  76

#endif
