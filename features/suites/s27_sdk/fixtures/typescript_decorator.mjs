import * as mvm from "../../../../crates/mvm-sdk/sdks/typescript/dist/index.js";

mvm.reset();
mvm.workload({ id: "bdd-decorator" });
mvm.app({
  name: "bdd-decorator",
  image: mvm.python_image(),
  resources: mvm.resources({ cpu: 1, memory_mb: 256, rootfs_size_mb: 512 }),
  entrypoint: mvm.entrypoint({ command: ["python", "-c", "print('ok')"] }),
})(() => undefined);

console.log(mvm.emitJson());
