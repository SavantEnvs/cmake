/* Turn LeakSanitizer off at build time for every fuzz and -standalone binary (leaks are not the bug
 * class this integration fuzzes for). ASan's memory-error checks and UBSan stay fully active. */
int __lsan_is_turned_off(void);
int __lsan_is_turned_off(void) { return 1; }
