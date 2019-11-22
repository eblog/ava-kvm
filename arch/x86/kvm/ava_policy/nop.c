
int nop_schedule(void *data)
{
    return 1;
}
EXPORT_SYMBOL_GPL(nop_schedule);

void nop_consume(void *data)
{
    return;
}
EXPORT_SYMBOL_GPL(nop_consume);
