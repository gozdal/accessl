PROJECT (accel)

SET(SOURCE accel_base.c accel_bn.c accel.c accel_gmp.c accel_mod_exp.c)

ADD_LIBRARY(accel STATIC ${SOURCE})
