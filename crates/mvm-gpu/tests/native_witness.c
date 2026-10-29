#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Resolve the same public ABI that a guest workload uses, without CUDA headers. */
#define LOAD(lib, name, args) \
    int (*name) args; \
    *(void **)(&name) = dlsym(lib, #name); \
    if (!name) { fprintf(stderr, "%s: %s\n", #name, dlerror()); return 1; }
#define CALL(expr) do { int rc = (expr); if (rc) { \
    fprintf(stderr, "%s returned %d\n", #expr, rc); return 1; } } while (0)

static const char ptx[] =
    ".version 6.0\n.target sm_50\n.address_size 64\n"
    ".visible .entry increment(.param .u64 data) {\n"
    ".reg .b64 %rd;\n.reg .b32 %r;\n"
    "ld.param.u64 %rd, [data];\nld.global.u32 %r, [%rd];\n"
    "add.u32 %r, %r, 37;\nst.global.u32 [%rd], %r;\nret;\n}\n";

int main(int argc, char **argv) {
    const char *rpc = getenv("MVM_GPU_RPC");
    if (argc != 3 || !rpc || strncmp(rpc, "unix:/", 6) || !rpc[6]) {
        fprintf(stderr, "usage: MVM_GPU_RPC=unix:/absolute/socket native_witness CUDA_SHIM NVML_SHIM\n");
        return 64;
    }
    void *cuda = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!cuda) { fprintf(stderr, "%s\n", dlerror()); return 1; }
    void *nvml = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!nvml) { fprintf(stderr, "%s\n", dlerror()); return 1; }
    LOAD(cuda, cuInit, (unsigned));
    LOAD(cuda, cuDriverGetVersion, (int *));
    LOAD(cuda, cuDeviceGetCount, (int *));
    LOAD(cuda, cuCtxCreate, (void **, unsigned, int));
    LOAD(cuda, cuCtxDestroy, (void *));
    LOAD(cuda, cuMemAlloc, (uint64_t *, size_t));
    LOAD(cuda, cuMemFree, (uint64_t));
    LOAD(cuda, cuMemcpyHtoD, (uint64_t, const void *, size_t));
    LOAD(cuda, cuMemcpyDtoH, (void *, uint64_t, size_t));
    LOAD(cuda, cuModuleLoadData, (void **, const void *));
    LOAD(cuda, cuModuleGetFunction, (void **, void *, const char *));
    LOAD(cuda, cuModuleUnload, (void *));
    LOAD(cuda, cuLaunchKernel, (void *, unsigned, unsigned, unsigned,
                               unsigned, unsigned, unsigned, unsigned,
                               void *, void **, void **));
    LOAD(cuda, cuCtxSynchronize, (void));
    LOAD(nvml, nvmlInit_v2, (void));
    LOAD(nvml, nvmlShutdown, (void));
    LOAD(nvml, nvmlSystemGetDriverVersion, (char *, unsigned));
    LOAD(nvml, nvmlDeviceGetCount_v2, (unsigned *));
    LOAD(nvml, nvmlDeviceGetHandleByIndex_v2, (unsigned, void **));
    LOAD(nvml, nvmlDeviceGetName, (void *, char *, unsigned));
    void *ctx = NULL, *module = NULL, *function = NULL, *device = NULL;
    uint64_t ptr = 0;
    uint32_t input = 105, output = 0;
    int version = 0;
    unsigned count = 0;
    char driver[128] = {0}, name[256] = {0};
    CALL(cuInit(0));
    int cuda_count = 0;
    CALL(cuDeviceGetCount(&cuda_count));
    if (cuda_count != 1) {
        fprintf(stderr, "requires exactly one CUDA device, got %d\n", cuda_count);
        return 1;
    }
    CALL(cuDriverGetVersion(&version));
    CALL(cuCtxCreate(&ctx, 0, 0));
    CALL(cuMemAlloc(&ptr, sizeof(input)));
    CALL(cuMemcpyHtoD(ptr, &input, sizeof(input)));
    CALL(cuModuleLoadData(&module, ptx));
    CALL(cuModuleGetFunction(&function, module, "increment"));
    void *params[] = { &ptr };
    CALL(cuLaunchKernel(function, 1, 1, 1, 1, 1, 1, 0, NULL, params, NULL));
    CALL(cuCtxSynchronize());
    CALL(cuMemcpyDtoH(&output, ptr, sizeof(output)));
    if (output != input + 37) {
        fprintf(stderr, "kernel correctness: expected 142, got %u\n", output);
        return 1;
    }
    CALL(cuModuleUnload(module));
    CALL(cuMemFree(ptr));
    CALL(cuCtxDestroy(ctx));
    CALL(nvmlInit_v2());
    CALL(nvmlSystemGetDriverVersion(driver, sizeof(driver)));
    CALL(nvmlDeviceGetCount_v2(&count));
    CALL(nvmlDeviceGetHandleByIndex_v2(0, &device));
    CALL(nvmlDeviceGetName(device, name, sizeof(name)));
    CALL(nvmlShutdown());
    /* Tab-separated fields are encoded as JSON by the owning runner. */
    printf("%d\t%u\t%s\t%s\t%u\n", version, count, driver, name, output);
    dlclose(nvml);
    dlclose(cuda);
    return 0;
}
