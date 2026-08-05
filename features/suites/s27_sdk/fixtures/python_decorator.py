import mvm

mvm.reset()
mvm.workload(id="bdd-decorator")


@mvm.app(
    name="bdd-decorator",
    source=mvm.local_path("."),
    image=mvm.python_image(),
    entrypoint=mvm.entrypoint(command=["python", "-c", "print('ok')"]),
    resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
)
def bdd_decorator() -> None:
    pass


print(mvm.emit_json())
