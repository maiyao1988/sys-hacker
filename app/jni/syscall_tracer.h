
#include <sys/types.h>

class ISysTracer {
public:
    virtual void run(pid_t pid) = 0;
};

ISysTracer *sys_tracer_create();
void sys_tracer_release(ISysTracer *&p);

