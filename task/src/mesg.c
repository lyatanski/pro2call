#include "mesg.h"

static int         mesg_level   = MESG_LEVEL_INFO;
static const void* mesg_data    = NULL;
static mesg_f      mesg_dbug_cb = NULL;
static mesg_f      mesg_info_cb = NULL;
static mesg_f      mesg_warn_cb = NULL;
static mesg_f      mesg_fail_cb = NULL;
static mesg_f      mesg_dead_cb = NULL;

void mesg_set_level(int level)
{
    mesg_level = level;
}

int mesg_get_level()
{
    return mesg_level;
}

void mesg_set_data(const void* arg_data)
{
    mesg_data = arg_data;
}

const void* mesg_get_data()
{
    return mesg_data;
}

void mesg_set_dbug_cb(mesg_f cb)
{
    mesg_dbug_cb = cb;
}

mesg_f mesg_get_dbug_cb()
{
    return mesg_dbug_cb;
}

void mesg_set_info_cb(mesg_f cb)
{
    mesg_info_cb = cb;
}

mesg_f mesg_get_info_cb()
{
    return mesg_info_cb;
}

void mesg_set_warn_cb(mesg_f cb)
{
    mesg_warn_cb = cb;
}

mesg_f mesg_get_warn_cb()
{
    return mesg_warn_cb;
}

void mesg_set_fail_cb(mesg_f cb)
{
    mesg_fail_cb = cb;
}

mesg_f mesg_get_fail_cb()
{
    return mesg_fail_cb;
}

void mesg_set_dead_cb(mesg_f cb)
{
    mesg_dead_cb = cb;
}

mesg_f mesg_get_dead_cb()
{
    return mesg_dead_cb;
}
