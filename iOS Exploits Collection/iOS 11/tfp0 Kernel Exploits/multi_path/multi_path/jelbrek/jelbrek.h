
void init_jelbrek(mach_port_t tfp0, uint64_t kernel_base);
kern_return_t trust_bin(const char *path);
BOOL unsandbox(pid_t pid);
void empower(pid_t pid);
BOOL get_root(pid_t pid);
